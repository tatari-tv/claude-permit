use std::io::{IsTerminal, Write};

/// Send `text` through a pager when stdout is a terminal.
/// Falls back to plain print if pager is unavailable or stdout is not a terminal.
pub fn page_output(text: &str, pager: Option<&str>) {
    let pager_cmd = pager.unwrap_or("less -R");
    if std::io::stdout().is_terminal() {
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
    print!("{text}");
}
