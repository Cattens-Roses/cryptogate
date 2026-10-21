use anyhow::{anyhow, ensure, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Gauge, Paragraph, Row, Table, Wrap},
    Frame, Terminal,
};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use wallet_core::{
    format_amount, parse_amount, vault::Vault, NetworkFactory, NetworkInfo, Payment, Snapshot,
};
use zeroize::Zeroizing;

const ACCENT: Color = Color::Rgb(110, 231, 183);
const MUTED: Color = Color::Rgb(141, 156, 175);
const BG: Color = Color::Rgb(15, 23, 36);

enum Command {
    Address,
    Prepare(String, u128, u64),
    Broadcast(Payment),
    CancelReview,
    Sync,
}
enum Update {
    Info(NetworkInfo),
    Snapshot(Snapshot),
    Status(String),
    Review(Payment),
    Failed(String),
    Sent(String),
    Fatal(String),
}

#[derive(Default)]
enum Screen {
    #[default]
    Dashboard,
    Send {
        fields: [String; 3],
        focus: usize,
    },
    Review(Payment),
}

struct App {
    info: NetworkInfo,
    snapshot: Snapshot,
    status: String,
    error: Option<String>,
    screen: Screen,
    offline: bool,
    ready: bool,
    busy: bool,
    scroll: usize,
}

impl App {
    fn new(offline: bool) -> Self {
        Self {
            info: NetworkInfo {
                id: "",
                name: "Wallet",
                ticker: "",
                decimals: 8,
                fee_rate_unit: "fee rate",
            },
            snapshot: Snapshot::default(),
            status: "Opening wallet · checking header cache…".into(),
            error: None,
            screen: Screen::Dashboard,
            offline,
            ready: false,
            busy: false,
            scroll: 0,
        }
    }
    fn update(&mut self, update: Update) {
        match update {
            Update::Info(info) => self.info = info,
            Update::Snapshot(s) => {
                if s.connected_peers > 0 && self.snapshot.peer != s.peer {
                    self.error = None;
                }
                self.snapshot = s;
                self.ready = true;
            }
            Update::Status(s) => {
                self.status = s;
            }
            Update::Review(p) => {
                self.screen = Screen::Review(p);
                self.busy = false;
                self.error = None;
            }
            Update::Failed(e) => {
                self.error = Some(e);
                self.busy = false;
            }
            Update::Sent(txid) => {
                self.screen = Screen::Dashboard;
                self.busy = false;
                self.status =
                    format!("Broadcast delivered to peer · awaiting confirmation · {txid}");
            }
            Update::Fatal(e) => {
                self.error = Some(e);
                self.status = "Wallet could not be opened · press q to exit".into();
            }
        }
    }

    fn key(&mut self, code: KeyCode, commands: &Sender<Command>) -> Result<bool> {
        if self.busy {
            return Ok(matches!(code, KeyCode::Char('q')));
        }
        match &mut self.screen {
            Screen::Dashboard => match code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
                KeyCode::Char('n') if self.ready => {
                    commands.send(Command::Address)?;
                    self.status = "Issuing a fresh receive address…".into();
                }
                KeyCode::Char('s') if self.ready && !self.offline => {
                    self.screen = Screen::Send {
                        fields: [String::new(), String::new(), "10".into()],
                        focus: 0,
                    };
                    self.error = None;
                }
                KeyCode::Char('r') if self.ready && !self.offline => {
                    commands.send(Command::Sync)?;
                    self.error = None;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.scroll =
                        (self.scroll + 1).min(self.snapshot.transactions.len().saturating_sub(1))
                }
                KeyCode::Up | KeyCode::Char('k') => self.scroll = self.scroll.saturating_sub(1),
                _ => {}
            },
            Screen::Send { fields, focus } => match code {
                KeyCode::Esc => {
                    self.screen = Screen::Dashboard;
                    self.error = None;
                }
                KeyCode::Tab | KeyCode::Down => *focus = (*focus + 1) % 3,
                KeyCode::BackTab | KeyCode::Up => *focus = (*focus + 2) % 3,
                KeyCode::Backspace => {
                    fields[*focus].pop();
                }
                KeyCode::Char(c) if !c.is_control() && fields[*focus].len() < 128 => {
                    fields[*focus].push(c)
                }
                KeyCode::Enter if *focus < 2 => *focus += 1,
                KeyCode::Enter => {
                    let parsed = parse_amount(&fields[1], self.info.decimals).and_then(|amount| {
                        let fee = fields[2]
                            .parse::<u64>()
                            .map_err(|_| anyhow!("Enter a whole-number fee rate"))?;
                        Ok((amount, fee))
                    });
                    match parsed {
                        Ok((amount, fee)) => {
                            commands.send(Command::Prepare(fields[0].clone(), amount, fee))?;
                            self.status = "Preparing signed payment for review…".into();
                            self.busy = true;
                            self.error = None;
                        }
                        Err(e) => self.error = Some(e.to_string()),
                    }
                }
                _ => {}
            },
            Screen::Review(payment) => match code {
                KeyCode::Esc | KeyCode::Char('n') => {
                    commands.send(Command::CancelReview)?;
                    self.screen = Screen::Dashboard;
                    self.error = None;
                }
                KeyCode::Char('y') => {
                    commands.send(Command::Broadcast(payment.clone()))?;
                    self.busy = true;
                    self.error = None;
                    self.status = "Broadcasting reviewed transaction…".into();
                }
                _ => {}
            },
        }
        Ok(false)
    }
}

fn worker(
    seed: Zeroizing<[u8; 64]>,
    factory: NetworkFactory,
    offline: bool,
    commands: Receiver<Command>,
    updates: Sender<(usize, Update)>,
    id: usize,
    cancel: Arc<AtomicBool>,
) {
    let send = |update| updates.send((id, update)).is_ok();
    let report = |message: &str| {
        let _ = send(Update::Status(message.to_owned()));
    };
    let mut network = match factory(&seed, &cancel, &report) {
        Ok(network) => network,
        Err(error) => {
            let _ = send(Update::Fatal(format!("{error:#}")));
            return;
        }
    };
    drop(seed);
    let _ = send(Update::Info(network.info()));
    let _ = send(Update::Snapshot(network.snapshot()));
    let mut next_sync = Instant::now();
    let mut reviewing = false;
    let mut sync_requested = !offline;
    let mut failure_count = 0u32;
    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if !offline && network.poll_activity().unwrap_or(false) {
            let _ = send(Update::Snapshot(network.snapshot()));
        }
        while let Ok(command) = commands.try_recv() {
            let result = match command {
                Command::Address => network.next_address().map(|_| {
                    let _ = send(Update::Status("Fresh receive address saved".into()));
                }),
                Command::Prepare(recipient, amount, fee) => {
                    network.prepare_payment(&recipient, amount, fee).map(|p| {
                        reviewing = true;
                        let _ = send(Update::Review(p));
                    })
                }
                Command::Broadcast(payment) => {
                    reviewing = false;
                    network.broadcast(&payment, &cancel).map(|_| {
                        let _ = send(Update::Sent(payment.txid));
                    })
                }
                Command::CancelReview => {
                    reviewing = false;
                    Ok(())
                }
                Command::Sync => {
                    reviewing = false;
                    sync_requested = true;
                    next_sync = Instant::now();
                    Ok(())
                }
            };
            if let Err(e) = result {
                let _ = send(Update::Failed(format!("{e:#}")));
            }
            let _ = send(Update::Snapshot(network.snapshot()));
        }
        if !offline && !reviewing && (sync_requested || Instant::now() >= next_sync) {
            match network.sync_step(&cancel) {
                Ok(done) => {
                    failure_count = 0;
                    sync_requested = !done;
                    if done {
                        next_sync = Instant::now() + Duration::from_secs(10);
                    }
                    let _ = send(Update::Status(network.sync_status().unwrap_or_else(|| {
                        if done {
                            "BIP157 scan complete · watching new blocks".into()
                        } else {
                            "BIP157 sync · headers and compact filters".into()
                        }
                    })));
                }
                Err(error) => {
                    network.disconnect();
                    failure_count = failure_count.saturating_add(1);
                    let seconds = if network.snapshot().connected_peers > 0 {
                        0
                    } else {
                        (5 * 2u64.pow(failure_count.min(4))).min(60)
                    };
                    sync_requested = false;
                    next_sync = Instant::now() + Duration::from_secs(seconds);
                    let _ = send(Update::Failed(format!("{error:#}")));
                    let _ = send(Update::Status(format!(
                        "Connection paused · retry in {seconds}s · r retries now"
                    )));
                }
            }
            let _ = send(Update::Snapshot(network.snapshot()));
        }
        if offline {
            let _ = send(Update::Status(
                "Offline · cached proof-verified state".into(),
            ));
        }
        if sync_requested && !offline && !reviewing {
            thread::yield_now();
        } else {
            thread::sleep(Duration::from_millis(50));
        }
    }
    drop(network);
}

struct ScreenGuard;
impl Drop for ScreenGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

pub(crate) struct NetworkSetup {
    pub name: &'static str,
    pub ticker: &'static str,
    pub factory: NetworkFactory,
}

struct NetworkView {
    app: App,
    commands: Sender<Command>,
}
struct Workspace {
    views: Vec<NetworkView>,
    active: usize,
}
impl Workspace {
    fn update(&mut self, id: usize, update: Update) {
        if let Some(view) = self.views.get_mut(id) {
            view.app.update(update);
        }
    }
    fn key(&mut self, code: KeyCode) -> Result<bool> {
        let app = &self.views[self.active].app;
        if matches!(app.screen, Screen::Dashboard) && !app.busy {
            let next = match code {
                KeyCode::Tab | KeyCode::Char(']') => Some((self.active + 1) % self.views.len()),
                KeyCode::BackTab | KeyCode::Char('[') => {
                    Some((self.active + self.views.len() - 1) % self.views.len())
                }
                KeyCode::Char(c @ '1'..='9') => Some((c as u8 - b'1') as usize),
                _ => None,
            };
            if let Some(index) = next {
                if index < self.views.len() {
                    self.active = index;
                }
                return Ok(false);
            }
        }
        let view = &mut self.views[self.active];
        view.app.key(code, &view.commands)
    }
}

struct Picker {
    selected: Vec<bool>,
    cursor: usize,
}
impl Picker {
    fn new(count: usize) -> Self {
        Self {
            selected: vec![true; count],
            cursor: 0,
        }
    }
    fn key(&mut self, code: KeyCode) -> Option<Vec<usize>> {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.cursor = (self.cursor + self.selected.len() - 1) % self.selected.len()
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = (self.cursor + 1) % self.selected.len()
            }
            KeyCode::Char(' ') => self.selected[self.cursor] = !self.selected[self.cursor],
            KeyCode::Char('a') => {
                let select = !self.selected.iter().all(|selected| *selected);
                self.selected.fill(select);
            }
            KeyCode::Enter => {
                let indices: Vec<_> = self
                    .selected
                    .iter()
                    .enumerate()
                    .filter_map(|(index, selected)| selected.then_some(index))
                    .collect();
                if !indices.is_empty() {
                    return Some(indices);
                }
            }
            _ => {}
        }
        None
    }
}

fn draw_picker(frame: &mut Frame, picker: &Picker, setups: &[NetworkSetup]) {
    frame.render_widget(
        Block::default().style(Style::default().bg(BG).fg(Color::White)),
        frame.area(),
    );
    let mut lines = vec![
        Line::styled(" Choose one or more networks", Style::default().fg(ACCENT)),
        Line::raw(""),
    ];
    for (index, setup) in setups.iter().enumerate() {
        lines.push(Line::styled(
            format!(
                " {} [{}] {} ({})",
                if picker.cursor == index { ">" } else { " " },
                if picker.selected[index] { "x" } else { " " },
                setup.name,
                setup.ticker
            ),
            Style::default().fg(if picker.cursor == index {
                ACCENT
            } else {
                Color::White
            }),
        ));
    }
    lines.extend([
        Line::raw(""),
        Line::raw(" Both selected networks run at the same time."),
        Line::raw(""),
        Line::raw(" Up/Down · Space toggle · a select all"),
        Line::raw(" Enter start · q / Esc quit"),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel(" ENGINECORE · Networks "))
            .wrap(Wrap { trim: false }),
        modal(frame.area(), 64, 13),
    );
}

fn spawn_workers(
    seed: &[u8; 64],
    setups: Vec<NetworkSetup>,
    offline: bool,
    cancel: &Arc<AtomicBool>,
) -> (
    Workspace,
    Receiver<(usize, Update)>,
    Vec<thread::JoinHandle<()>>,
) {
    let (updates, update_rx) = mpsc::channel();
    let mut views = Vec::new();
    let mut handles = Vec::new();
    for (id, setup) in setups.into_iter().enumerate() {
        let (commands, command_rx) = mpsc::channel();
        let mut app = App::new(offline);
        app.info.name = setup.name;
        app.info.ticker = setup.ticker;
        views.push(NetworkView { app, commands });
        let seed = Zeroizing::new(*seed);
        let updates = updates.clone();
        let worker_cancel = cancel.clone();
        handles.push(thread::spawn(move || {
            worker(
                seed,
                setup.factory,
                offline,
                command_rx,
                updates,
                id,
                worker_cancel,
            )
        }));
    }
    (Workspace { views, active: 0 }, update_rx, handles)
}

pub fn run(vault: Vault, setups: Vec<NetworkSetup>, choose: bool, offline: bool) -> Result<()> {
    ensure!(!setups.is_empty(), "No networks available");
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        previous(info);
    }));
    enable_raw_mode()?;
    let guard = ScreenGuard;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;
    let setups = if choose {
        let mut picker = Picker::new(setups.len());
        let selected = loop {
            terminal.draw(|frame| draw_picker(frame, &picker, &setups))?;
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                    || (key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c'))
                {
                    return Ok(());
                }
                if let Some(indices) = picker.key(key.code) {
                    break indices;
                }
            }
        };
        setups
            .into_iter()
            .enumerate()
            .filter_map(|(index, setup)| selected.contains(&index).then_some(setup))
            .collect()
    } else {
        setups
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let (mut workspace, update_rx, handles) = spawn_workers(vault.seed(), setups, offline, &cancel);
    let result = (|| -> Result<()> {
        loop {
            for (id, update) in update_rx.try_iter() {
                workspace.update(id, update);
            }
            terminal.draw(|frame| draw_workspace(frame, &workspace))?;
            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        if key.modifiers.contains(KeyModifiers::CONTROL)
                            && key.code == KeyCode::Char('c')
                        {
                            break;
                        }
                        if workspace.key(key.code)? {
                            break;
                        }
                    }
                    Event::Paste(text) => {
                        let app = &mut workspace.views[workspace.active].app;
                        if let Screen::Send { fields, focus } = &mut app.screen {
                            for c in text
                                .chars()
                                .filter(|c| !c.is_control())
                                .take(128 - fields[*focus].len())
                            {
                                fields[*focus].push(c);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    })();
    cancel.store(true, Ordering::Relaxed);
    drop(guard);
    let mut panicked = false;
    // Retain the single vault lock until every network writer and relay has stopped.
    for handle in handles {
        panicked |= handle.join().is_err();
    }
    drop(vault);
    if panicked {
        return Err(anyhow!("Network worker panicked"));
    }
    result
}

fn draw_workspace(frame: &mut Frame, workspace: &Workspace) {
    draw(frame, &workspace.views[workspace.active].app);
    let area = frame.area();
    if area.width < 64 || area.height < 24 {
        return;
    }
    let mut tabs = Vec::new();
    for (index, view) in workspace.views.iter().enumerate() {
        let app = &view.app;
        tabs.push(Span::styled(
            format!(
                " [{}] {} {} {}/{} ",
                index + 1,
                app.info.ticker,
                format_amount(app.snapshot.balance, app.info.decimals),
                app.snapshot.connected_peers,
                app.snapshot.max_peers
            ),
            Style::default()
                .fg(if workspace.active == index {
                    ACCENT
                } else {
                    MUTED
                })
                .add_modifier(if workspace.active == index {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        ));
    }
    let mode = if workspace.views[workspace.active].app.offline {
        "OFFLINE"
    } else {
        "SPV"
    };
    let title = if workspace.views.len() > 1 {
        format!(
            " ENGINECORE · {mode} · Tab / 1-{} networks ",
            workspace.views.len().min(9)
        )
    } else {
        format!(" ENGINECORE · {mode} / MAINNET ")
    };
    frame.render_widget(
        Paragraph::new(Line::from(tabs)).block(panel(&title)),
        Rect::new(area.x + 1, area.y + 1, area.width - 2, 3),
    );
}

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(48, 65, 85)))
}

fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(BG).fg(Color::White)),
        area,
    );
    if area.width < 64 || area.height < 24 {
        frame.render_widget(
            Paragraph::new("EngineCore · resize to at least 64 × 24\nq / Ctrl+C exits")
                .style(Style::default().fg(ACCENT)),
            area,
        );
        return;
    }
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(4),
        Constraint::Length(4),
        Constraint::Length(4),
        Constraint::Min(3),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .margin(1)
    .split(area);
    let mode = if app.offline {
        "OFFLINE"
    } else {
        "SPV / BIP157 / MAINNET"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " ENGINECORE ",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" /  {}", app.info.name)),
            Span::styled(format!("    {mode}"), Style::default().fg(MUTED)),
        ]))
        .block(panel(" Multi-network wallet ")),
        rows[0],
    );
    let balances =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                format!(
                    " {} {}",
                    format_amount(app.snapshot.balance, app.info.decimals),
                    app.info.ticker
                ),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                format!(
                    " Pending +{} / -{}",
                    format_amount(app.snapshot.pending_incoming, app.info.decimals),
                    format_amount(app.snapshot.pending_outgoing, app.info.decimals)
                ),
                Style::default().fg(MUTED),
            ),
        ])
        .block(panel(if app.snapshot.scanned < app.snapshot.height {
            " Verified balance (partial scan) "
        } else {
            " Verified balance "
        })),
        balances[0],
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                " {} {}",
                format_amount(app.snapshot.spendable, app.info.decimals),
                app.info.ticker
            )),
            Line::styled(
                format!(" {}", app.snapshot.spend_note),
                Style::default().fg(MUTED),
            ),
        ])
        .block(panel(" Spendable ")),
        balances[1],
    );
    let s = &app.snapshot;
    let address = if s.address.is_empty() {
        "Loading receive address…"
    } else {
        &s.address
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(format!(" {address}"), Style::default().fg(ACCENT)),
            Line::styled(
                format!(" {}    [n] fresh address", s.receive_note),
                Style::default().fg(MUTED),
            ),
        ])
        .block(panel(" Receive "))
        .wrap(Wrap { trim: false }),
        rows[2],
    );
    let sync = Layout::vertical([Constraint::Length(3), Constraint::Length(1)]).split(rows[3]);
    let denominator = s.height.max(s.peer_height).max(1);
    let ratio = (s.scanned.min(s.height) as f64 / denominator as f64).clamp(0.0, 1.0);
    frame.render_widget(
        Gauge::default()
            .block(panel(" SPV progress "))
            .ratio(ratio)
            .gauge_style(Style::default().fg(ACCENT).bg(Color::Rgb(30, 41, 59)))
            .label(format!(
                "headers {}  scanned {}  recent {}",
                s.height,
                s.scanned,
                s.recent_scanned.max(s.scanned)
            )),
        sync[0],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(
                    " Peers: {}/{} · mempool {}",
                    s.connected_peers, s.max_peers, s.mempool_status
                ),
                Style::default().fg(if s.connected_peers > 0 { ACCENT } else { MUTED }),
            ),
            Span::styled(
                if s.peer.is_empty() {
                    " · disconnected".into()
                } else {
                    format!(" · {}", s.peer)
                },
                Style::default().fg(MUTED),
            ),
        ])),
        sync[1],
    );
    let history = s.transactions.iter().skip(app.scroll).map(|tx| {
        let (sign, amount) = if tx.received >= tx.sent {
            ("+", tx.received - tx.sent)
        } else {
            ("−", tx.sent - tx.received)
        };
        Row::new(vec![
            Cell::from(if tx.height == 0 {
                "pending".into()
            } else {
                tx.height.to_string()
            }),
            Cell::from(format!(
                "{sign}{}",
                format_amount(amount, app.info.decimals)
            )),
            Cell::from(tx.txid.clone()),
        ])
    });
    let mut table = Table::new(
        history,
        [
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Min(16),
        ],
    )
    .block(panel(if s.transactions.is_empty() {
        " Transactions · no proven wallet activity yet "
    } else {
        " Transactions · ↑/↓ scroll "
    }));
    if rows[4].height >= 4 {
        table = table.header(
            Row::new(["Height", "Net amount", "Transaction ID"]).style(Style::default().fg(MUTED)),
        );
    }
    frame.render_widget(table, rows[4]);
    let message = app.error.as_deref().unwrap_or(&app.status);
    frame.render_widget(
        Paragraph::new(message)
            .style(Style::default().fg(if app.error.is_some() {
                Color::LightRed
            } else {
                MUTED
            }))
            .wrap(Wrap { trim: true })
            .block(panel(" Status ")),
        rows[5],
    );
    frame.render_widget(
        Paragraph::new(" [s] send   [n] new address   [r] sync / reconnect   [q] quit")
            .style(Style::default().fg(MUTED)),
        rows[6],
    );
    match &app.screen {
        Screen::Dashboard => {}
        Screen::Send { fields, focus } => {
            let area = modal(area, 68, 15);
            frame.render_widget(Clear, area);
            let inner = panel(" Send ").style(Style::default().bg(BG)).inner(area);
            frame.render_widget(panel(" Send ").style(Style::default().bg(BG)), area);
            let lines = vec![
                Line::styled(
                    format!(" {} · {}", app.info.name, app.info.ticker),
                    Style::default().fg(MUTED),
                ),
                Line::raw(""),
                field("To", &fields[0], *focus == 0),
                Line::raw(""),
                field(
                    &format!("Amount {}", app.info.ticker),
                    &fields[1],
                    *focus == 1,
                ),
                Line::raw(""),
                field(app.info.fee_rate_unit, &fields[2], *focus == 2),
                Line::raw(""),
                Line::styled(
                    " Tab changes field · Enter continues · Esc cancels",
                    Style::default().fg(MUTED),
                ),
                Line::raw(""),
                Line::styled(
                    app.error.as_deref().unwrap_or(if app.busy {
                        " Preparing payment…"
                    } else {
                        " Nothing is broadcast until you confirm the review."
                    }),
                    Style::default().fg(if app.error.is_some() {
                        Color::LightRed
                    } else {
                        MUTED
                    }),
                ),
            ];
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        }
        Screen::Review(payment) => {
            let area = modal(area, 76, 17);
            frame.render_widget(Clear, area);
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled(
                        " Check the recipient and amounts before broadcasting.",
                        Style::default().fg(ACCENT),
                    ),
                    Line::raw(""),
                    Line::raw(format!(" To:     {}", payment.recipient)),
                    Line::raw(""),
                    Line::raw(format!(
                        " Amount: {} {}",
                        format_amount(payment.amount, app.info.decimals),
                        app.info.ticker
                    )),
                    Line::raw(format!(
                        " Fee:    {} {}",
                        format_amount(payment.fee, app.info.decimals),
                        app.info.ticker
                    )),
                    Line::raw(format!(
                        " Total:  {} {}",
                        format_amount(payment.amount + payment.fee, app.info.decimals),
                        app.info.ticker
                    )),
                    Line::raw(""),
                    Line::styled(
                        format!(" Txid: {}", payment.txid),
                        Style::default().fg(MUTED),
                    ),
                    Line::raw(""),
                    Line::styled(
                        if app.busy {
                            " Broadcasting…"
                        } else {
                            " [y] CONFIRM AND BROADCAST    [n / Esc] cancel"
                        },
                        Style::default().fg(ACCENT),
                    ),
                    Line::styled(
                        app.error
                            .as_deref()
                            .unwrap_or(" Peer delivery is not a blockchain confirmation."),
                        Style::default().fg(if app.error.is_some() {
                            Color::LightRed
                        } else {
                            MUTED
                        }),
                    ),
                ])
                .wrap(Wrap { trim: false })
                .block(panel(" Review payment ").style(Style::default().bg(BG))),
                area,
            );
        }
    }
}

fn field<'a>(label: &str, value: &str, focused: bool) -> Line<'a> {
    Line::styled(
        format!(
            " {} {label}: {value}{}",
            if focused { "›" } else { " " },
            if focused { "▏" } else { "" }
        ),
        Style::default().fg(if focused { ACCENT } else { Color::White }),
    )
}

fn modal(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(4));
    let height = height.min(area.height.saturating_sub(2));
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn picker_selects_one_or_both_and_rejects_an_empty_selection() {
        let mut picker = Picker::new(2);
        assert_eq!(picker.key(KeyCode::Enter), Some(vec![0, 1]));
        picker.key(KeyCode::Char(' '));
        assert_eq!(picker.key(KeyCode::Enter), Some(vec![1]));
        picker.key(KeyCode::Down);
        picker.key(KeyCode::Char(' '));
        assert_eq!(picker.key(KeyCode::Enter), None);
        picker.key(KeyCode::Char('a'));
        assert_eq!(picker.key(KeyCode::Enter), Some(vec![0, 1]));
    }

    fn workspace_for_test() -> (Workspace, Vec<Receiver<Command>>) {
        let mut views = Vec::new();
        let mut receivers = Vec::new();
        for (name, ticker, address) in [
            ("Litecoin", "LTC", "ltc1qexample"),
            ("Bitcoin", "BTC", "bc1qexample"),
        ] {
            let (commands, receiver) = mpsc::channel();
            let mut app = App::new(false);
            app.info.name = name;
            app.info.ticker = ticker;
            app.ready = true;
            app.snapshot.address = address.into();
            app.snapshot.max_peers = 3;
            views.push(NetworkView { app, commands });
            receivers.push(receiver);
        }
        (Workspace { views, active: 0 }, receivers)
    }

    #[test]
    fn tabs_route_actions_to_their_network_and_cannot_switch_a_payment_review() {
        let (mut workspace, receivers) = workspace_for_test();
        workspace.key(KeyCode::Tab).unwrap();
        workspace.key(KeyCode::Char('n')).unwrap();
        assert!(matches!(receivers[1].try_recv().unwrap(), Command::Address));
        assert!(receivers[0].try_recv().is_err());
        let payment = Payment {
            recipient: "bc1qexample".into(),
            amount: 1000,
            fee: 100,
            txid: "bitcoin-payment".into(),
            raw: vec![],
        };
        workspace.update(1, Update::Review(payment));
        workspace.update(
            0,
            Update::Snapshot(Snapshot {
                balance: 123,
                ..Snapshot::default()
            }),
        );
        workspace.key(KeyCode::BackTab).unwrap();
        workspace.key(KeyCode::Char('1')).unwrap();
        assert_eq!(workspace.active, 1);
        assert!(matches!(workspace.views[1].app.screen, Screen::Review(_)));
        workspace.key(KeyCode::Char('y')).unwrap();
        assert!(
            matches!(receivers[1].try_recv().unwrap(), Command::Broadcast(payment) if payment.txid == "bitcoin-payment")
        );
        assert!(receivers[0].try_recv().is_err());
        assert_eq!(workspace.views[0].app.snapshot.balance, 123);
        assert_eq!(workspace.views[1].app.snapshot.balance, 0);
        workspace.update(1, Update::Sent("bitcoin-payment".into()));
        workspace.key(KeyCode::BackTab).unwrap();
        assert_eq!(workspace.active, 0);
    }

    struct FakeNetwork {
        steps: u32,
        address: String,
    }
    impl wallet_core::Network for FakeNetwork {
        fn info(&self) -> NetworkInfo {
            NetworkInfo {
                id: "fake",
                name: "Fake",
                ticker: "FAKE",
                decimals: 8,
                fee_rate_unit: "sat/vB",
            }
        }
        fn snapshot(&self) -> Snapshot {
            Snapshot {
                address: self.address.clone(),
                scanned: self.steps,
                height: self.steps,
                ..Snapshot::default()
            }
        }
        fn next_address(&mut self) -> Result<String> {
            self.address = "fast-next-address".into();
            Ok(self.address.clone())
        }
        fn sync_step(&mut self, _cancel: &AtomicBool) -> Result<bool> {
            self.steps += 1;
            Ok(true)
        }
        fn disconnect(&mut self) {}
        fn prepare_payment(&mut self, _: &str, _: u128, _: u64) -> Result<Payment> {
            Err(anyhow!("Unused in concurrency test"))
        }
        fn broadcast(&mut self, _: &Payment, _: &AtomicBool) -> Result<()> {
            Err(anyhow!("Unused in concurrency test"))
        }
    }

    #[test]
    fn a_slow_open_does_not_block_the_other_network_and_vault_lock_spans_all_workers() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = Vault::create(dir.path(), "parallel-test-password", None).unwrap();
        let (release, gate) = mpsc::channel();
        let slow: NetworkFactory = Box::new(move |_, _, _| {
            gate.recv_timeout(Duration::from_secs(5))?;
            Ok(Box::new(FakeNetwork {
                steps: 0,
                address: "slow".into(),
            }))
        });
        let fast: NetworkFactory = Box::new(|_, _, _| {
            Ok(Box::new(FakeNetwork {
                steps: 0,
                address: "fast".into(),
            }))
        });
        let setups = vec![
            NetworkSetup {
                name: "Slow",
                ticker: "SLOW",
                factory: slow,
            },
            NetworkSetup {
                name: "Fast",
                ticker: "FAST",
                factory: fast,
            },
        ];
        let cancel = Arc::new(AtomicBool::new(false));
        let (mut workspace, updates, handles) = spawn_workers(vault.seed(), setups, false, &cancel);
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut fast_progress = false;
        let mut routed_address = false;
        while Instant::now() < deadline {
            let Ok((id, update)) = updates.recv_timeout(Duration::from_millis(100)) else {
                continue;
            };
            workspace.update(id, update);
            if workspace.views[1].app.snapshot.scanned > 0 && !fast_progress {
                fast_progress = true;
                workspace.key(KeyCode::Tab).unwrap();
                workspace.key(KeyCode::Char('n')).unwrap();
            }
            if workspace.views[1].app.snapshot.address == "fast-next-address" {
                routed_address = true;
                break;
            }
        }
        let slow_still_opening = !workspace.views[0].app.ready;
        let locked_while_running = Vault::open(dir.path(), "parallel-test-password").is_err();
        cancel.store(true, Ordering::Relaxed);
        release.send(()).unwrap();
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(Vault::open(dir.path(), "parallel-test-password").is_err());
        drop(vault);
        assert!(Vault::open(dir.path(), "parallel-test-password").is_ok());
        assert!(fast_progress && routed_address && slow_still_opening && locked_while_running);
    }

    #[test]
    fn workspace_and_picker_render_both_networks_at_supported_sizes() {
        let setups = vec![
            NetworkSetup {
                name: "Litecoin",
                ticker: "LTC",
                factory: Box::new(|_, _, _| unreachable!()),
            },
            NetworkSetup {
                name: "Bitcoin",
                ticker: "BTC",
                factory: Box::new(|_, _, _| unreachable!()),
            },
        ];
        let (mut workspace, _) = workspace_for_test();
        for (width, height) in [(100, 34), (80, 24), (64, 24)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| draw_picker(frame, &Picker::new(2), &setups))
                .unwrap();
            let screen: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(screen.contains("Litecoin") && screen.contains("Bitcoin"));
            terminal
                .draw(|frame| draw_workspace(frame, &workspace))
                .unwrap();
            let screen: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(
                screen.contains("LTC") && screen.contains("BTC") && screen.contains("ltc1qexample")
            );
            workspace.active = 1;
            terminal
                .draw(|frame| draw_workspace(frame, &workspace))
                .unwrap();
            let screen: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(screen.contains("bc1qexample"));
            workspace.active = 0;
        }
    }
    #[test]
    fn dashboard_and_payment_review_render_at_supported_sizes() {
        for (width, height) in [(100, 34), (80, 24), (64, 24), (30, 10)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            let mut app = App::new(true);
            app.snapshot.address = "ltc1qexample".into();
            terminal.draw(|f| draw(f, &app)).unwrap();
            let screen: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(screen.contains("ENGINECORE") || screen.contains("EngineCore"));
            app.screen = Screen::Review(Payment {
                recipient: "ltc1qexample".into(),
                amount: 100_000,
                fee: 200,
                txid: "ab".repeat(32),
                raw: vec![],
            });
            terminal.draw(|f| draw(f, &app)).unwrap();
        }
    }
    #[test]
    fn send_requires_separate_confirmation_key() {
        let (commands, rx) = mpsc::channel();
        let mut app = App::new(false);
        app.screen = Screen::Review(Payment {
            recipient: "ltc1qexample".into(),
            amount: 1_000,
            fee: 100,
            txid: "abc".into(),
            raw: vec![],
        });
        app.key(KeyCode::Enter, &commands).unwrap();
        assert!(rx.try_recv().is_err());
        app.key(KeyCode::Char('y'), &commands).unwrap();
        assert!(matches!(rx.try_recv().unwrap(), Command::Broadcast(_)));
    }
}
