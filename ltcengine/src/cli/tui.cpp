#include "ltc/cli/tui.hpp"

#include "ltc/cli/background_sync.hpp"
#include "ltc/net/spv.hpp"
#include "ltc/params.hpp"
#include "ltc/util/error_log.hpp"
#include "ltc/util/fs.hpp"
#include "ltc/wallet/wallet.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <conio.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace ltc {
namespace tui {
namespace {

#ifdef _WIN32
enum class Color : WORD {
  Reset = 7,
  Dim = 8,
  Red = 12,
  Green = 10,
  Yellow = 14,
  Cyan = 11,
  White = 15,
  Title = 11,
  Accent = 14,
  Menu = 15,
  HudBg = BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
  SelBg = BACKGROUND_BLUE | BACKGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN |
          FOREGROUND_BLUE | FOREGROUND_INTENSITY,
};

HANDLE stdout_handle() { return GetStdHandle(STD_OUTPUT_HANDLE); }

void set_color(Color c) {
  SetConsoleTextAttribute(stdout_handle(), static_cast<WORD>(c));
}

void clear_screen() {
  HANDLE h = stdout_handle();
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  if (!GetConsoleScreenBufferInfo(h, &csbi)) return;
  DWORD cells = static_cast<DWORD>(csbi.dwSize.X * csbi.dwSize.Y);
  DWORD written = 0;
  COORD home{0, 0};
  FillConsoleOutputCharacterA(h, ' ', cells, home, &written);
  FillConsoleOutputAttribute(h, csbi.wAttributes, cells, home, &written);
  SetConsoleCursorPosition(h, home);
}

void hide_cursor(bool hide) {
  HANDLE h = stdout_handle();
  CONSOLE_CURSOR_INFO info;
  if (!GetConsoleCursorInfo(h, &info)) return;
  info.bVisible = hide ? FALSE : TRUE;
  SetConsoleCursorInfo(h, &info);
}

void goto_xy(int x, int y) {
  COORD c{static_cast<SHORT>(x), static_cast<SHORT>(y)};
  SetConsoleCursorPosition(stdout_handle(), c);
}

int console_width() {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  if (!GetConsoleScreenBufferInfo(stdout_handle(), &csbi)) return 80;
  return csbi.srWindow.Right - csbi.srWindow.Left + 1;
}

int read_key_raw() {
  int c = _getch();
  if (c == 0 || c == 224) {
    int e = _getch();
    if (e == 72) return -1;
    if (e == 80) return -2;
    if (e == 75) return -3;
    if (e == 77) return -4;
    return 0;
  }
  return c;
}

int poll_key(int wait_ms) {
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(wait_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    if (_kbhit()) return read_key_raw();
    Sleep(40);
  }
  return 0;
}
#else
enum class Color { Reset, Dim, Red, Green, Yellow, Cyan, White, Title, Accent, Menu, HudBg, SelBg };

void set_color(Color c) {
  switch (c) {
    case Color::Reset:
      std::cout << "\033[0m";
      break;
    case Color::Dim:
      std::cout << "\033[90m";
      break;
    case Color::Red:
      std::cout << "\033[91m";
      break;
    case Color::Green:
      std::cout << "\033[92m";
      break;
    case Color::Yellow:
      std::cout << "\033[93m";
      break;
    case Color::Cyan:
    case Color::Title:
      std::cout << "\033[96m";
      break;
    case Color::Accent:
      std::cout << "\033[93m";
      break;
    case Color::White:
    case Color::Menu:
      std::cout << "\033[97m";
      break;
    case Color::HudBg:
      std::cout << "\033[44;97m";
      break;
    case Color::SelBg:
      std::cout << "\033[44;97m";
      break;
  }
}

void clear_screen() { std::cout << "\033[2J\033[H" << std::flush; }
void hide_cursor(bool hide) { std::cout << (hide ? "\033[?25l" : "\033[?25h") << std::flush; }
void goto_xy(int x, int y) { std::cout << "\033[" << (y + 1) << ";" << (x + 1) << "H" << std::flush; }

int console_width() {
  winsize ws{};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
  return 80;
}

// Temporary non-canonical stdin (arrow keys / password). Restores on destruction.
struct ScopedTermios {
  termios old_{};
  bool active_ = false;
  explicit ScopedTermios(bool echo) {
    if (!isatty(STDIN_FILENO)) return;
    if (tcgetattr(STDIN_FILENO, &old_) != 0) return;
    termios raw = old_;
    raw.c_lflag &= ~static_cast<tcflag_t>(ICANON | ECHO | ECHOE | ECHOK | ECHONL);
    if (echo) raw.c_lflag |= ECHO;
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) return;
    active_ = true;
  }
  ~ScopedTermios() {
    if (active_) tcsetattr(STDIN_FILENO, TCSANOW, &old_);
  }
  ScopedTermios(const ScopedTermios&) = delete;
  ScopedTermios& operator=(const ScopedTermios&) = delete;
};

std::string g_key_pending;

int take_pending_key() {
  if (g_key_pending.empty()) return 0;
  unsigned char c0 = static_cast<unsigned char>(g_key_pending[0]);
  if (c0 == 0x1b) {
    if (g_key_pending.size() >= 3 && g_key_pending[1] == '[') {
      char e = g_key_pending[2];
      g_key_pending.erase(0, 3);
      if (e == 'A') return -1;
      if (e == 'B') return -2;
      if (e == 'C') return -4;
      if (e == 'D') return -3;
      return 0;
    }
    // Incomplete escape — wait for more bytes unless it's a lone / non-CSI ESC.
    if (g_key_pending.size() == 1) {
      g_key_pending.clear();
      return 27;
    }
    if (g_key_pending[1] != '[') {
      g_key_pending.erase(0, 1);
      return 27;
    }
    return 0;
  }
  g_key_pending.erase(0, 1);
  return static_cast<int>(c0);
}

int read_key_raw() {
  ScopedTermios raw(false);
  if (int k = take_pending_key()) return k;
  unsigned char buf[16];
  ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
  if (n <= 0) return 0;
  g_key_pending.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
  return take_pending_key();
}

int poll_key(int wait_ms) {
  ScopedTermios raw(false);
  if (int k = take_pending_key()) return k;

  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(wait_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                                      std::chrono::steady_clock::now())
                    .count();
    if (left <= 0) break;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    timeval tv{};
    tv.tv_sec = static_cast<time_t>(left / 1000);
    tv.tv_usec = static_cast<suseconds_t>((left % 1000) * 1000);
    int sel = ::select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv);
    if (sel < 0) {
      if (errno == EINTR) continue;
      return 0;
    }
    if (sel == 0) continue;
    unsigned char buf[16];
    ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) continue;
    g_key_pending.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
    // If we only have ESC so far, wait briefly for the rest of an arrow sequence.
    if (g_key_pending.size() == 1 && static_cast<unsigned char>(g_key_pending[0]) == 0x1b) {
      fd_set fds2;
      FD_ZERO(&fds2);
      FD_SET(STDIN_FILENO, &fds2);
      timeval tv2{};
      tv2.tv_usec = 50000;
      if (::select(STDIN_FILENO + 1, &fds2, nullptr, nullptr, &tv2) > 0) {
        n = ::read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) g_key_pending.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
      }
    }
    if (int k = take_pending_key()) return k;
  }
  return 0;
}
#endif

void print(Color c, const std::string& s) {
  set_color(c);
  std::cout << s;
  set_color(Color::Reset);
}

void println(Color c, const std::string& s) {
  print(c, s);
  std::cout << "\n";
}

void hr() {
  println(Color::Dim, "────────────────────────────────────────────────────────────");
}

std::string format_ltc(int64_t sats) {
  bool neg = sats < 0;
  int64_t v = neg ? -sats : sats;
  int64_t whole = v / 100000000;
  int64_t frac = v % 100000000;
  std::ostringstream oss;
  if (neg) oss << "-";
  oss << whole << "." << std::setw(8) << std::setfill('0') << frac << " LTC";
  return oss.str();
}

std::string prompt_line(const std::string& label, bool secret = false) {
  print(Color::Accent, label);
  set_color(Color::White);
  std::string line;
  if (secret) {
    std::cout << std::flush;
#ifdef _WIN32
    for (;;) {
      int c = _getch();
      if (c == '\r' || c == '\n') {
        std::cout << "\n";
        break;
      }
      if (c == 3) throw std::runtime_error("cancelled");
      if (c == 8 || c == 127) {
        if (!line.empty()) {
          line.pop_back();
          std::cout << "\b \b" << std::flush;
        }
        continue;
      }
      if (c == 0 || c == 224) {
        (void)_getch();
        continue;
      }
      if (c >= 32 && c < 127) {
        line.push_back(static_cast<char>(c));
        std::cout << '*' << std::flush;
      }
    }
#else
    {
      ScopedTermios raw(false);
      for (;;) {
        unsigned char ch = 0;
        ssize_t n = ::read(STDIN_FILENO, &ch, 1);
        if (n < 0) {
          if (errno == EINTR) continue;
          break;
        }
        if (n == 0) {
          // Non-blocking: wait for a key.
          fd_set fds;
          FD_ZERO(&fds);
          FD_SET(STDIN_FILENO, &fds);
          timeval tv{};
          tv.tv_sec = 30;
          if (::select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) <= 0) continue;
          continue;
        }
        if (ch == '\r' || ch == '\n') {
          std::cout << "\n" << std::flush;
          break;
        }
        if (ch == 3) throw std::runtime_error("cancelled");
        if (ch == 8 || ch == 127) {
          if (!line.empty()) {
            line.pop_back();
            std::cout << "\b \b" << std::flush;
          }
          continue;
        }
        if (ch >= 32 && ch < 127) {
          line.push_back(static_cast<char>(ch));
          std::cout << '*' << std::flush;
        }
      }
    }
#endif
    set_color(Color::Reset);
    return line;
  }
  std::getline(std::cin, line);
  set_color(Color::Reset);
  return line;
}

Color conn_color(const SyncStatus& st) {
  auto c = sync_conn_label(st);
  if (c == "connected" || c.find("connected") == 0) return Color::Green;
  if (c == "connecting" || c == "reconnecting") return Color::Yellow;
  if (c == "disconnected") return Color::Red;
  return Color::Dim;
}

void write_line_at(int y, Color c, const std::string& s, int width) {
  if (width < 40) width = 80;
  goto_xy(0, y);
  set_color(c);
  std::string out = s;
  if (static_cast<int>(out.size()) > width) out.resize(static_cast<size_t>(width));
  std::cout << out;
  for (int i = static_cast<int>(out.size()); i < width; ++i) std::cout << ' ';
  set_color(Color::Reset);
}

void clear_line_at(int y, int width) {
  write_line_at(y, Color::Reset, "", width);
}

// Top-right corner HUD — updates in place without clearing the screen.
void draw_corner_hud(const SyncStatus& st) {
  std::string line1 = sync_progress_label(st);
  std::string line2 = "status: " + sync_conn_label(st);
  if (st.phase == SyncStatus::Phase::SyncingHeaders) line2 += " · downloading";
  else if (st.phase == SyncStatus::Phase::Watching) line2 += " · live";
  else if (st.phase == SyncStatus::Phase::Connecting) line2 += " · connecting";
  else if (st.phase == SyncStatus::Phase::Reconnecting) line2 += " · retrying";
  else if (st.rescanning) line2 += " · rescanning";

  int width = console_width();
  if (width < 40) width = 80;
  int box_w = static_cast<int>(std::max(line1.size(), line2.size())) + 4;
  if (box_w > width - 2) box_w = width - 2;
  int x = width - box_w - 1;
  if (x < 0) x = 0;

  // Erase previous HUD if it moved / shrank so leftovers don't ghost.
  static int prev_x = -1, prev_w = 0;
  if (prev_w > 0 && (prev_x != x || prev_w != box_w)) {
    for (int row = 0; row < 2; ++row) {
      goto_xy(prev_x, row);
      for (int i = 0; i < prev_w; ++i) std::cout << ' ';
    }
  }
  prev_x = x;
  prev_w = box_w;

  auto pad = [box_w](const std::string& s) {
    std::string out = " " + s;
    while (static_cast<int>(out.size()) < box_w - 1) out.push_back(' ');
    if (static_cast<int>(out.size()) > box_w - 1) out.resize(static_cast<size_t>(box_w - 1));
    out.push_back(' ');
    return out;
  };

  goto_xy(x, 0);
  set_color(Color::HudBg);
  std::cout << pad(line1.substr(0, static_cast<size_t>(box_w - 2)));
  set_color(Color::Reset);

  goto_xy(x, 1);
  set_color(Color::HudBg);
  std::cout << pad(line2.substr(0, static_cast<size_t>(box_w - 2)));
  set_color(Color::Reset);
  std::cout << std::flush;
}

// Fixed-height sync panel redrawn in place (pads/clears unused rows).
constexpr int kSyncPanelLines = 9;

int draw_sync_panel_at(int top_y, const SyncStatus& st) {
  int width = console_width();
  if (width < 40) width = 80;
  std::vector<std::pair<Color, std::string>> lines;
  lines.push_back({Color::Dim, "────────────────────────────────────────────────────────────"});
  lines.push_back({conn_color(st), "  " + sync_progress_label(st)});
  lines.push_back({conn_color(st),
                   "  status: " + sync_conn_label(st) + "   phase: " + sync_phase_name(st.phase)});
  if (st.rescanning || st.phase == SyncStatus::Phase::SyncingHeaders ||
      (st.phase == SyncStatus::Phase::Watching && st.target_height > st.tip_height + 10)) {
    std::ostringstream r;
    r << "  rate ";
    if (st.headers_per_sec > 0)
      r << static_cast<int>(st.headers_per_sec + 0.5) << " hdr/s";
    else
      r << "…";
    r << "   " << format_eta(st.eta_seconds);
    lines.push_back({Color::Accent, r.str()});
  }
  {
    std::ostringstream b;
    b << "  balance " << format_ltc(st.balance_sats) << "   matched txs " << st.matched_txs;
    lines.push_back({Color::Accent, b.str()});
  }
  if (st.peers > 0) {
    std::ostringstream p;
    p << "  peers " << st.peers;
    if (st.peer_height > 0) p << "   peer height " << st.peer_height;
    if (!st.peer_agent.empty()) p << "   " << st.peer_agent;
    lines.push_back({Color::Dim, p.str()});
  }
  if (!st.detail.empty()) lines.push_back({Color::Dim, "  " + st.detail});
  if (!st.last_error.empty() &&
      (st.phase == SyncStatus::Phase::Error || st.phase == SyncStatus::Phase::Reconnecting))
    lines.push_back({Color::Red, "  last error: " + st.last_error});
  lines.push_back({Color::Dim, "────────────────────────────────────────────────────────────"});

  for (int i = 0; i < kSyncPanelLines; ++i) {
    if (i < static_cast<int>(lines.size()))
      write_line_at(top_y + i, lines[static_cast<size_t>(i)].first, lines[static_cast<size_t>(i)].second,
                    width);
    else
      clear_line_at(top_y + i, width);
  }
  std::cout << std::flush;
  return kSyncPanelLines;
}

void draw_sync_panel(const SyncStatus& st) {
  // Streaming fallback for one-shot screens (not the live menu).
  hr();
  println(conn_color(st), "  " + sync_progress_label(st));
  println(conn_color(st), "  status: " + sync_conn_label(st) + "   phase: " + sync_phase_name(st.phase));
  if (st.phase == SyncStatus::Phase::SyncingHeaders ||
      (st.phase == SyncStatus::Phase::Watching && st.target_height > st.tip_height + 10)) {
    std::ostringstream r;
    r << "  rate ";
    if (st.headers_per_sec > 0)
      r << static_cast<int>(st.headers_per_sec + 0.5) << " hdr/s";
    else
      r << "…";
    r << "   " << format_eta(st.eta_seconds);
    println(Color::Accent, r.str());
  }
  std::ostringstream b;
  b << "  balance " << format_ltc(st.balance_sats) << "   matched txs " << st.matched_txs;
  println(Color::Accent, b.str());
  if (st.peers > 0) {
    std::ostringstream p;
    p << "  peers " << st.peers;
    if (st.peer_height > 0) p << "   peer height " << st.peer_height;
    if (!st.peer_agent.empty()) p << "   " << st.peer_agent;
    println(Color::Dim, p.str());
  }
  if (!st.detail.empty()) println(Color::Dim, "  " + st.detail);
  if (!st.last_error.empty() &&
      (st.phase == SyncStatus::Phase::Error || st.phase == SyncStatus::Phase::Reconnecting))
    println(Color::Red, "  last error: " + st.last_error);
  hr();
}

using StatusFn = std::function<SyncStatus()>;

void draw_menu_items_at(int top_y, const std::vector<std::string>& items, int selected) {
  int width = console_width();
  if (width < 40) width = 80;
  for (int i = 0; i < static_cast<int>(items.size()); ++i) {
    std::ostringstream row;
    row << "  " << (i == selected ? ">" : " ") << " " << items[static_cast<size_t>(i)];
    std::string text = row.str();
    goto_xy(0, top_y + i);
    if (i == selected) {
      set_color(Color::SelBg);
      std::cout << text;
      for (int p = static_cast<int>(text.size()); p < 56 && p < width; ++p) std::cout << ' ';
      set_color(Color::Reset);
      for (int p = 56; p < width; ++p) std::cout << ' ';
    } else {
      set_color(Color::Menu);
      if (static_cast<int>(text.size()) > width) text.resize(static_cast<size_t>(width));
      std::cout << text;
      for (int p = static_cast<int>(text.size()); p < width; ++p) std::cout << ' ';
      set_color(Color::Reset);
    }
  }
  std::cout << std::flush;
}

int menu_select(const std::string& title, const std::vector<std::string>& items, StatusFn status_fn,
                int selected = 0) {
  if (items.empty()) return -1;
  if (selected < 0) selected = 0;
  if (selected >= static_cast<int>(items.size())) selected = static_cast<int>(items.size()) - 1;

  hide_cursor(true);
  const int width = std::max(console_width(), 40);
  const int panel_top = 3;
  const int menu_title_y = panel_top + kSyncPanelLines;
  const int menu_y = menu_title_y + 2;
  const int help_y = menu_y + static_cast<int>(items.size()) + 1;

  auto paint_chrome = [&]() {
    clear_screen();
    goto_xy(0, 0);
    write_line_at(0, Color::Title, "  ltcengine", width);
    write_line_at(1, Color::Dim, "  Litecoin SPV wallet", width);
    clear_line_at(2, width);
    write_line_at(menu_title_y, Color::Accent, "  " + title, width);
    clear_line_at(menu_title_y + 1, width);
    write_line_at(help_y, Color::Dim, "  ↑/↓ move   Enter select   Esc/q back", width);
  };

  auto refresh_status = [&]() {
    if (!status_fn) {
      for (int i = 0; i < kSyncPanelLines; ++i) {
        if (i == 0 || i == kSyncPanelLines - 1)
          write_line_at(panel_top + i, Color::Dim,
                        "────────────────────────────────────────────────────────────", width);
        else
          clear_line_at(panel_top + i, width);
      }
      return;
    }
    auto st = status_fn();
    draw_sync_panel_at(panel_top, st);
    draw_corner_hud(st);
  };

  paint_chrome();
  refresh_status();
  draw_menu_items_at(menu_y, items, selected);

  for (;;) {
    int k = poll_key(350);
    if (k == 0) {
      // Idle tick — only status/HUD, not the whole screen.
      refresh_status();
      continue;
    }
    if (k == -1) {
      selected = (selected + static_cast<int>(items.size()) - 1) % static_cast<int>(items.size());
      draw_menu_items_at(menu_y, items, selected);
    } else if (k == -2) {
      selected = (selected + 1) % static_cast<int>(items.size());
      draw_menu_items_at(menu_y, items, selected);
    } else if (k == '\r' || k == '\n' || k == ' ') {
      hide_cursor(false);
      return selected;
    } else if (k == 27 || k == 'q' || k == 'Q') {
      hide_cursor(false);
      return -1;
    } else if (k >= '1' && k <= '9') {
      int idx = k - '1';
      if (idx < static_cast<int>(items.size())) {
        hide_cursor(false);
        return idx;
      }
    }
  }
}

void pause_ok(const std::string& msg = "Press any key...") {
  std::cout << "\n";
  println(Color::Dim, "  " + msg);
  (void)poll_key(60000);
}

void show_error(const std::string& msg) {
  log_error(msg, "tui");
  println(Color::Red, "  error: " + msg);
  pause_ok();
}

struct Session {
  std::string datadir;
  std::string password;
  std::unique_ptr<Wallet> wallet;
  BackgroundSync sync;

  StatusFn status_fn() {
    return [this]() {
      auto st = sync.status();
      if (wallet) {
        std::lock_guard<std::mutex> lock(sync.wallet_mutex());
        st.balance_sats = wallet->balance();
      }
      return st;
    };
  }

  void start_sync() {
    if (!wallet) return;
    set_error_log_dir(datadir);
    sync.start(wallet.get(), password);
  }

  void stop_sync() { sync.stop(); }
};

bool wallet_exists(const std::string& dir) {
  return fs::file_exists(fs::join(dir, "wallet.dat"));
}

void action_create(Session& s) {
  s.stop_sync();
  clear_screen();
  println(Color::Title, "  Create wallet");
  hr();
  std::string dir = prompt_line("  data directory [" + s.datadir + "]: ");
  if (dir.empty()) dir = s.datadir;
  std::string pass = prompt_line("  password: ", true);
  if (pass.empty()) {
    show_error("password required");
    return;
  }
  std::string pass2 = prompt_line("  confirm password: ", true);
  if (pass != pass2) {
    show_error("passwords do not match");
    return;
  }
  try {
    fs::ensure_dir(dir);
    set_error_log_dir(dir);
    auto w = Wallet::create_new(dir, pass);
    std::string addr = w.get_new_address();
    w.save(pass);
    clear_screen();
    println(Color::Green, "  Wallet created — background sync starting");
    hr();
    println(Color::Accent, "  Write down this mnemonic (shown once):");
    println(Color::White, "  " + w.mnemonic());
    std::cout << "\n";
    println(Color::Cyan, "  First address:");
    println(Color::White, "  " + addr);
    s.datadir = dir;
    s.password = pass;
    s.wallet = std::make_unique<Wallet>(std::move(w));
    s.start_sync();
    pause_ok();
  } catch (const std::exception& e) {
    show_error(e.what());
  }
}

void action_import(Session& s) {
  s.stop_sync();
  clear_screen();
  println(Color::Title, "  Import mnemonic");
  hr();
  std::string dir = prompt_line("  data directory [" + s.datadir + "]: ");
  if (dir.empty()) dir = s.datadir;
  std::string mnemonic = prompt_line("  mnemonic: ");
  std::string pass = prompt_line("  password: ", true);
  if (pass.empty() || mnemonic.empty()) {
    show_error("mnemonic and password required");
    return;
  }
  try {
    fs::ensure_dir(dir);
    set_error_log_dir(dir);
    auto w = Wallet::import_mnemonic(dir, mnemonic, pass);
    std::string addr = w.get_new_address();
    w.save(pass);
    clear_screen();
    println(Color::Green, "  Imported — background sync starting");
    println(Color::Cyan, "  First address: " + addr);
    s.datadir = dir;
    s.password = pass;
    s.wallet = std::make_unique<Wallet>(std::move(w));
    s.start_sync();
    pause_ok();
  } catch (const std::exception& e) {
    show_error(e.what());
  }
}

void action_open(Session& s) {
  s.stop_sync();
  clear_screen();
  println(Color::Title, "  Open wallet");
  hr();
  std::string dir = prompt_line("  data directory [" + s.datadir + "]: ");
  if (dir.empty()) dir = s.datadir;
  if (!wallet_exists(dir)) {
    show_error("no wallet.dat in " + dir);
    return;
  }
  std::string pass = prompt_line("  password: ", true);
  try {
    set_error_log_dir(dir);
    auto w = Wallet::load(dir, pass);
    s.datadir = dir;
    s.password = pass;
    s.wallet = std::make_unique<Wallet>(std::move(w));
    s.start_sync();
    println(Color::Green, "  Opened — background sync running");
    println(Color::Dim, "  Balance " + format_ltc(s.wallet->balance()));
    pause_ok();
  } catch (const std::exception& e) {
    show_error(e.what());
  }
}

void action_addresses(Session& s) {
  if (!s.wallet) {
    show_error("open a wallet first");
    return;
  }
  int kind = menu_select("New receive address",
                         {"Native SegWit (ltc1q)", "Legacy (L...)", "Nested SegWit (M...)",
                          "Taproot (ltc1p)", "List watched addresses", "Back"},
                         s.status_fn());
  if (kind < 0 || kind == 5) return;
  try {
    if (kind == 4) {
      clear_screen();
      draw_corner_hud(s.status_fn()());
      goto_xy(0, 3);
      println(Color::Title, "  Watched addresses");
      hr();
      std::lock_guard<std::mutex> lock(s.sync.wallet_mutex());
      for (const auto& a : s.wallet->all_addresses()) {
        if (a.change) continue;
        std::ostringstream line;
        line << "  [" << wallet_address_type_name(a.type) << " #" << a.index << "] " << a.address;
        println(Color::White, line.str());
      }
      pause_ok();
      return;
    }
    WalletAddressType t = WalletAddressType::Native;
    if (kind == 1) t = WalletAddressType::Legacy;
    if (kind == 2) t = WalletAddressType::Nested;
    if (kind == 3) t = WalletAddressType::Taproot;
    std::string addr;
    {
      std::lock_guard<std::mutex> lock(s.sync.wallet_mutex());
      addr = s.wallet->get_new_address(t);
      s.wallet->save(s.password);
    }
    s.sync.request_bloom_refresh();
    clear_screen();
    draw_corner_hud(s.status_fn()());
    goto_xy(0, 3);
    println(Color::Green, "  New address");
    hr();
    println(Color::White, "  " + addr);
    pause_ok();
  } catch (const std::exception& e) {
    show_error(e.what());
  }
}

void action_balance(Session& s) {
  if (!s.wallet) {
    show_error("open a wallet first");
    return;
  }
  clear_screen();
  draw_corner_hud(s.status_fn()());
  goto_xy(0, 3);
  draw_sync_panel(s.status_fn()());
  println(Color::Title, "  Balance / UTXOs");
  hr();
  std::lock_guard<std::mutex> lock(s.sync.wallet_mutex());
  println(Color::Green, "  " + format_ltc(s.wallet->balance()));
  println(Color::Dim, "  " + std::to_string(s.wallet->balance()) + " sats");
  std::cout << "\n";
  println(Color::Accent, "  UTXOs:");
  size_t n = 0;
  for (const auto& u : s.wallet->utxos()) {
    if (u.spent) continue;
    ++n;
    std::ostringstream line;
    line << "  " << to_hex(u.outpoint.txid.data(), u.outpoint.txid.size(), true) << ":"
         << u.outpoint.vout << "  " << u.value << " sats";
    println(Color::Dim, line.str());
  }
  if (n == 0) println(Color::Dim, "  (none)");
  pause_ok();
}

void action_sync_status(Session& s) {
  hide_cursor(true);
  const int width = std::max(console_width(), 40);
  const int panel_top = 3;
  const int help_y = panel_top + kSyncPanelLines + 1;

  clear_screen();
  write_line_at(0, Color::Title, "  ltcengine", width);
  write_line_at(1, Color::Dim, "  Litecoin SPV wallet", width);
  write_line_at(2, Color::Title, "  Background sync", width);
  write_line_at(help_y, Color::Dim, "  Continuous P2P sync — Esc/q back", width);

  for (;;) {
    auto st = s.status_fn()();
    draw_sync_panel_at(panel_top, st);
    draw_corner_hud(st);
    int k = poll_key(400);
    if (k == 27 || k == 'q' || k == 'Q') break;
  }
  hide_cursor(false);
}

void action_send(Session& s) {
  if (!s.wallet) {
    show_error("open a wallet first");
    return;
  }
  clear_screen();
  draw_corner_hud(s.status_fn()());
  goto_xy(0, 3);
  println(Color::Title, "  Send Litecoin");
  hr();
  int64_t bal = 0;
  {
    std::lock_guard<std::mutex> lock(s.sync.wallet_mutex());
    bal = s.wallet->balance();
  }
  println(Color::Dim, "  Available: " + format_ltc(bal));
  std::string to = prompt_line("  to address: ");
  std::string amt_s = prompt_line("  amount (sats): ");
  std::string fee_s = prompt_line("  fee rate sats/vB [10]: ");
  try {
    int64_t amount = std::stoll(amt_s);
    int64_t fee = fee_s.empty() ? params::kDefaultFeeRateSatPerVb : std::stoll(fee_s);
    print(Color::Yellow, "  Broadcast " + std::to_string(amount) + " sats to " + to + "? [y/N] ");
    std::string conf;
    std::getline(std::cin, conf);
    if (conf != "y" && conf != "Y") {
      println(Color::Dim, "  Cancelled");
      pause_ok();
      return;
    }
    s.sync.pause();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    std::string txid;
    {
      std::lock_guard<std::mutex> lock(s.sync.wallet_mutex());
      net::SpvNode spv(s.datadir);
      // One peer is enough for broadcast; keep connect fast.
      if (!spv.connect_peers(1, 2, false)) throw std::runtime_error("no peers for broadcast");
      txid = s.wallet->send(spv, to, amount, fee);
      s.wallet->save(s.password);
    }
    s.sync.resume();
    s.sync.request_bloom_refresh();
    println(Color::Green, "  Broadcast txid:");
    println(Color::White, "  " + txid);
    pause_ok();
  } catch (const std::exception& e) {
    s.sync.resume();
    show_error(e.what());
  }
}

void action_mnemonic(Session& s) {
  if (!s.wallet) {
    show_error("open a wallet first");
    return;
  }
  clear_screen();
  println(Color::Yellow, "  Show recovery mnemonic?");
  print(Color::Accent, "  Type YES to reveal: ");
  std::string conf;
  std::getline(std::cin, conf);
  if (conf != "YES") {
    println(Color::Dim, "  Cancelled");
    pause_ok();
    return;
  }
  println(Color::White, "  " + s.wallet->mnemonic());
  pause_ok("Press any key to clear...");
}

}  // namespace

int run(const std::string& default_datadir) {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode = 0;
  if (GetConsoleMode(h, &mode)) {
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(h, mode);
  }
#endif

  Session s;
  s.datadir = default_datadir.empty() ? std::string("./wallet") : default_datadir;
  set_error_log_dir(s.datadir);

  if (wallet_exists(s.datadir)) {
    clear_screen();
    println(Color::Title, "  ltcengine");
    hr();
    println(Color::Dim, "  Found wallet at " + s.datadir);
    print(Color::Accent, "  Open it now? [Y/n] ");
    std::string ans;
    std::getline(std::cin, ans);
    if (ans.empty() || ans == "y" || ans == "Y") {
      try {
        std::string pass = prompt_line("  password: ", true);
        s.wallet = std::make_unique<Wallet>(Wallet::load(s.datadir, pass));
        s.password = pass;
        s.start_sync();
      } catch (const std::exception& e) {
        log_error(e.what(), "tui/open");
        println(Color::Red, std::string("  ") + e.what());
        pause_ok();
      }
    }
  }

  for (;;) {
    std::vector<std::string> items;
    if (!s.wallet) {
      items = {"Create wallet", "Import mnemonic", "Open wallet", "Quit"};
      int sel = menu_select("Home", items, {});
      if (sel < 0 || sel == 3) break;
      if (sel == 0) action_create(s);
      if (sel == 1) action_import(s);
      if (sel == 2) action_open(s);
      continue;
    }

    items = {"New address", "Balance / UTXOs", "Sync status (live)", "Send", "Show mnemonic",
             "Close wallet", "Quit"};
    int sel = menu_select("Wallet", items, s.status_fn());
    if (sel < 0) continue;
    if (sel == 0) action_addresses(s);
    else if (sel == 1) action_balance(s);
    else if (sel == 2) action_sync_status(s);
    else if (sel == 3) action_send(s);
    else if (sel == 4) action_mnemonic(s);
    else if (sel == 5) {
      s.stop_sync();
      s.wallet.reset();
      s.password.clear();
    } else if (sel == 6) {
      break;
    }
  }

  s.stop_sync();
  hide_cursor(false);
  clear_screen();
  println(Color::Dim, "  bye");
  return 0;
}

}  // namespace tui
}  // namespace ltc
