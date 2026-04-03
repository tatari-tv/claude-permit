use std::io::{IsTerminal, Write};
use terminal_size::{Height, terminal_size};

/// Send `text` through a pager only when output exceeds the terminal height.
/// Falls back to plain print if not a terminal, output fits, or pager is unavailable.
pub fn page_output(text: &str, pager: Option<&str>) {
    if std::io::stdout().is_terminal() {
        let line_count = text.lines().count();
        let term_height = terminal_size().map(|(_, Height(h))| h as usize).unwrap_or(24);

        if line_count > term_height {
            let pager_cmd = pager.unwrap_or("less -R");
            let mut parts = pager_cmd.split_whitespace();
            let cmd = parts.next().unwrap_or("less");
            let args: Vec<&str> = parts.collect();
            if let Ok(mut child) = std::process::Command::new(cmd)
                .args(&args)
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                let _ = child.wait();
                return;
            }
        }
    }
    print!("{text}");
}
