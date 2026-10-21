//! Startup console art from repo-root `logo.txt` / `napis.txt`.

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
/// Soft teal for the ASCII wordmark (one accent, not a rainbow).
const WORDMARK: u8 = 116;
/// Warm cream for the product line.
const TITLE: u8 = 230;

pub fn print() {
    let mut out = String::new();
    out.push('\n');
    out.push_str(&logo_ansi());
    out.push('\n');
    out.push_str(&paint(include_str!("../../../napis.txt"), WORDMARK, false));
    out.push('\n');
    out.push_str(&paint("  NO-KYC CRYPTOCURRENCY PAYMENT API\n", TITLE, true));
    out.push('\n');
    out.push_str(DIM);
    out.push_str("  shared SPV scan · idle until invoice · auto-forward");
    out.push_str(RESET);
    out.push_str("\n\n");
    print!("{out}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

fn logo_ansi() -> String {
    let raw = include_str!("../../../logo.txt");
    let body = raw
        .trim()
        .strip_prefix("printf \"")
        .or_else(|| raw.trim().strip_prefix("printf '"))
        .unwrap_or(raw.trim());
    let body = body
        .strip_suffix("\";")
        .or_else(|| body.strip_suffix("';"))
        .or_else(|| body.strip_suffix('"'))
        .unwrap_or(body);
    unescape_shell(body)
}

fn unescape_shell(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('e') | Some('E') => out.push('\x1b'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn paint(text: &str, color: u8, bold: bool) -> String {
    let mut out = String::new();
    if bold {
        out.push_str(BOLD);
    }
    out.push_str(&format!("\x1b[38;5;{color}m"));
    out.push_str(text);
    if !text.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(RESET);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_decodes_escape_sequences() {
        let logo = logo_ansi();
        assert!(logo.contains('\x1b'), "logo should contain ANSI escapes");
        assert!(!logo.contains("printf"));
        assert!(!logo.contains("\\e["));
    }

    #[test]
    fn wordmark_and_title_use_single_color() {
        let mark = paint("CARTENS", WORDMARK, false);
        assert_eq!(mark.matches("\x1b[38;5;").count(), 1);
        let title = paint("NO-KYC", TITLE, true);
        assert!(title.contains("NO-KYC"));
        assert_eq!(title.matches("\x1b[38;5;").count(), 1);
    }
}
