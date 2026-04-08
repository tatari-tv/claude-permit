use serde::Serialize;
use std::fmt;

use crate::config::{Config, ListConfig, ListMode};

/// Risk classification for a permission rule or tool invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskTier {
    Safe,
    Moderate,
    Dangerous,
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            RiskTier::Safe => "safe",
            RiskTier::Moderate => "moderate",
            RiskTier::Dangerous => "dangerous",
        })
    }
}

impl RiskTier {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "safe" => Some(RiskTier::Safe),
            "moderate" => Some(RiskTier::Moderate),
            "dangerous" => Some(RiskTier::Dangerous),
            _ => None,
        }
    }
}

/// Recommendation for an audited permission rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Recommendation {
    Promote,
    Keep,
    Narrow,
    Remove,
    Deny,
    Dupe,
}

impl fmt::Display for Recommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Recommendation::Promote => "promote",
            Recommendation::Keep => "keep",
            Recommendation::Narrow => "narrow",
            Recommendation::Remove => "remove",
            Recommendation::Deny => "deny",
            Recommendation::Dupe => "dupe",
        })
    }
}

/// Returns true if `broad` covers everything `narrow` covers — i.e., `narrow` is redundant.
///
/// Two cases:
/// - Bash: `Bash(X:*)` subsumes `Bash(Y:*)` when Y starts with "X " (word-boundary prefix)
/// - File tools: `Tool(**)` subsumes `Tool(<any other pattern>)`
pub fn subsumes(broad: &str, narrow: &str) -> bool {
    if broad == narrow {
        return false;
    }

    // Bash subsumption: Bash(X:*) subsumes Bash(Y:*) when Y starts with "X "
    if let (Some(bx), Some(ny)) = (extract_bash_pattern(broad), extract_bash_pattern(narrow)) {
        return ny.starts_with(&format!("{bx} "));
    }

    // File-tool subsumption: Tool(**) subsumes Tool(<anything else>)
    if let (Some((bt, bp)), Some((nt, np))) = (split_paren(broad), split_paren(narrow)) {
        return bt == nt && bp == "**" && np != "**";
    }

    false
}

/// Split "Tool(pattern)" into ("Tool", "pattern"), or None.
fn split_paren(rule: &str) -> Option<(&str, &str)> {
    let i = rule.find('(')?;
    if !rule.ends_with(')') {
        return None;
    }
    Some((&rule[..i], &rule[i + 1..rule.len() - 1]))
}

// --- Built-in defaults ---

/// Default bash patterns that are permanently denied (blocks execution when enforce-deny is on).
const DEFAULT_DENY: &[&str] = &[
    "git tag -d",
    "git push * :refs/tags/",
    "git push * --delete * tag",
    "rm ",
    "cd &&",
];

/// Default MCP tools classified as dangerous (write/mutation operations).
const DEFAULT_MCP_WRITE_PREFIXES: &[&str] = &[
    "mcp__slack__conversations_add_message",
    "mcp__atlassian__createJiraIssue",
    "mcp__atlassian__editJiraIssue",
    "mcp__atlassian__createConfluencePage",
    "mcp__atlassian__updateConfluencePage",
    "mcp__atlassian__addCommentToJiraIssue",
    "mcp__atlassian__transitionJiraIssue",
    "mcp__pagerduty__create_incident",
    "mcp__pagerduty__manage_incidents",
    "mcp__pagerduty__create_status_page_post",
    "mcp__multi-account-github__create_pr",
    "mcp__multi-account-github__merge_pr",
    "mcp__multi-account-github__close_pr",
    "mcp__multi-account-github__comment_pr",
    "mcp__multi-account-github__create_release",
];

/// Default read-only Bash commands (first word or "first second" prefix).
const DEFAULT_SAFE_BASH_COMMANDS: &[&str] = &[
    "ls",
    "tree",
    "stat",
    "wc",
    "cat",
    "head",
    "tail",
    "find",
    "grep",
    "rg",
    "fd",
    "jq",
    "yq",
    "echo",
    "env",
    "ps",
    "pgrep",
    "uname",
    "dmesg",
    "lspci",
    "lsmod",
    "modinfo",
    "ip",
    "ss",
    "ping",
    "nslookup",
    "dig",
    "nmcli",
    "iwconfig",
    "journalctl",
    "mount",
    "lsblk",
    "blkid",
    "getent",
    "avahi-resolve",
    "tailscale status",
    "dpkg",
    "apt list",
    "systemctl status",
    "systemctl is-enabled",
    "git status",
    "git diff",
    "git log",
    "git show",
    "git show-ref",
    "git ls-tree",
    "git branch",
    "git stash",
    "git fetch",
    "docker ps",
    "docker inspect",
    "docker logs",
    "docker version",
    "gh api",
    "gh pr view",
    "gh pr list",
    "gh pr checks",
    "gh run view",
    "gh run list",
];

/// Default moderate Bash commands (local writes, reversible).
const DEFAULT_MODERATE_BASH_COMMANDS: &[&str] = &[
    "git commit",
    "git push",
    "git add",
    "git rm",
    "git mv",
    "git merge",
    "git rebase",
    "git checkout",
    "git reset",
    "git clean",
    "git tag",
    "git pull",
    "cargo",
    "otto",
    "bump",
    "mkdir",
    "chmod",
    "docker compose",
    "docker stop",
    "docker run",
    "docker system",
    "python3",
    "uv",
    "pipx",
    "npm",
    "pnpm",
    "gh pr create",
    "curl",
];

/// Default overly broad patterns (triggers Narrow recommendation).
const DEFAULT_BROAD_PATTERNS: &[&str] = &[
    "Bash(git:*)",
    "Bash(docker:*)",
    "Bash(sudo:*)",
    "Bash(yes:*)",
];

// --- Rules ---

/// Resolved runtime rules, built from built-in defaults merged with user config.
pub struct Rules {
    pub enforce_deny: bool,
    pub deny_patterns: Vec<String>,
    pub safe_commands: Vec<String>,
    pub moderate_commands: Vec<String>,
    pub mcp_write_tools: Vec<String>,
    pub broad_patterns: Vec<String>,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            enforce_deny: false,
            deny_patterns: DEFAULT_DENY.iter().map(|s| s.to_string()).collect(),
            safe_commands: DEFAULT_SAFE_BASH_COMMANDS.iter().map(|s| s.to_string()).collect(),
            moderate_commands: DEFAULT_MODERATE_BASH_COMMANDS.iter().map(|s| s.to_string()).collect(),
            mcp_write_tools: DEFAULT_MCP_WRITE_PREFIXES.iter().map(|s| s.to_string()).collect(),
            broad_patterns: DEFAULT_BROAD_PATTERNS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Rules {
    pub fn from_config(config: &Config) -> Self {
        Self {
            enforce_deny: config.enforce_deny,
            deny_patterns: resolve_list(DEFAULT_DENY, &config.deny_patterns),
            safe_commands: resolve_list(DEFAULT_SAFE_BASH_COMMANDS, &config.safe_commands),
            moderate_commands: resolve_list(DEFAULT_MODERATE_BASH_COMMANDS, &config.moderate_commands),
            mcp_write_tools: resolve_list(DEFAULT_MCP_WRITE_PREFIXES, &config.mcp_write_tools),
            broad_patterns: resolve_list(DEFAULT_BROAD_PATTERNS, &config.broad_patterns),
        }
    }

    /// Check if a command matches any deny pattern.
    pub fn matches_deny_list(&self, command: &str) -> bool {
        let cmd = command.trim();
        self.deny_patterns.iter().any(|pattern| {
            if pattern.contains('*') {
                glob_match(pattern, cmd)
            } else if pattern == "cd &&" {
                // Special case: "cd <path> && ..." pattern
                cmd.starts_with("cd ") && cmd.contains("&&")
            } else {
                cmd.starts_with(pattern.as_str())
            }
        })
    }

    /// Classify a permission rule string like "Bash(git status:*)" or "Edit(src/**/*.rs)".
    pub fn classify_rule(&self, rule: &str) -> RiskTier {
        if let Some(inner) = extract_bash_pattern(rule) {
            return self.classify_bash_command(inner);
        }

        if rule == "Edit" || rule == "Write" || rule == "Edit(**)" || rule == "Write(**)" {
            return RiskTier::Dangerous;
        }

        if rule.starts_with("Edit(") || rule.starts_with("Write(") {
            return RiskTier::Moderate;
        }

        // Bare Read or Read(**) is carte blanche filesystem access - moderate risk
        if rule == "Read" || rule == "Read(**)" {
            return RiskTier::Moderate;
        }

        if rule == "Glob" || rule == "Grep" || rule == "Glob(**)" || rule == "Grep(**)" {
            return RiskTier::Safe;
        }

        if rule.starts_with("Read(") || rule.starts_with("Glob(") || rule.starts_with("Grep(") {
            return RiskTier::Safe;
        }

        if rule.starts_with("WebFetch(") || rule == "WebSearch" {
            return RiskTier::Safe;
        }

        if rule.starts_with("Skill(") {
            return RiskTier::Safe;
        }

        if rule.starts_with("mcp__") {
            return self.classify_mcp_tool(rule);
        }

        // Unknown tool type - default to moderate
        RiskTier::Moderate
    }

    /// Classify a raw tool invocation (tool_name + tool_input).
    pub fn classify_tool_input(&self, tool_name: &str, normalized_input: &str) -> RiskTier {
        match tool_name {
            "Bash" => self.classify_bash_command(normalized_input),
            "Edit" | "Write" => RiskTier::Moderate,
            "Read" | "Glob" | "Grep" => RiskTier::Safe,
            "WebFetch" | "WebSearch" => RiskTier::Safe,
            name if name.starts_with("mcp__") => self.classify_mcp_tool(name),
            _ => RiskTier::Moderate,
        }
    }

    /// Determine recommendation for a rule given its risk tier and source.
    pub fn recommend(&self, tier: RiskTier, source: &str, rule: &str) -> Recommendation {
        // Permanently denied patterns
        if let Some(cmd) = extract_bash_pattern(rule)
            && self.matches_deny_list(cmd)
        {
            return Recommendation::Deny;
        }

        // Overly broad patterns
        if self.is_overly_broad(rule) {
            return Recommendation::Narrow;
        }

        match (tier, source) {
            // Safe rules in local should be promoted to global
            (RiskTier::Safe, "local") => Recommendation::Promote,
            // Moderate rules in local - keep where they are
            (RiskTier::Moderate, "local") => Recommendation::Keep,
            // Dangerous rules in local - recommend removal
            (RiskTier::Dangerous, "local") => Recommendation::Remove,
            // Everything in global is already where it should be
            (_, "global") => Recommendation::Keep,
            _ => Recommendation::Keep,
        }
    }

    fn classify_bash_command(&self, cmd: &str) -> RiskTier {
        let cmd = cmd.trim();

        // Check deny list first
        if self.matches_deny_list(cmd) {
            return RiskTier::Dangerous;
        }

        // sudo prefix is always dangerous
        if cmd.starts_with("sudo ") {
            return RiskTier::Dangerous;
        }

        // git push --force is dangerous
        if cmd.starts_with("git push") && (cmd.contains("--force") || cmd.contains("-f")) {
            return RiskTier::Dangerous;
        }

        // Env var assignments (e.g. GH_TOKEN="..." cmd) are one-time specific invocations
        if starts_with_env_var(cmd) {
            return RiskTier::Dangerous;
        }

        // git -C <path> is a path-locked invocation that shouldn't be permanently allowed
        if cmd.starts_with("git -C ") {
            return RiskTier::Dangerous;
        }

        // bash -c is an arbitrary shell escape and should not be permanently allowed
        if cmd.starts_with("bash -c") {
            return RiskTier::Dangerous;
        }

        // Check safe commands (longest prefix match)
        if matches_command_list(cmd, &self.safe_commands) {
            return RiskTier::Safe;
        }

        // Check moderate commands
        if matches_command_list(cmd, &self.moderate_commands) {
            return RiskTier::Moderate;
        }

        // Unknown command - default to moderate
        RiskTier::Moderate
    }

    fn classify_mcp_tool(&self, tool: &str) -> RiskTier {
        let base = tool.split('(').next().unwrap_or(tool);
        if self.mcp_write_tools.iter().any(|prefix| base.starts_with(prefix.as_str())) {
            RiskTier::Dangerous
        } else {
            RiskTier::Moderate
        }
    }

    fn is_overly_broad(&self, rule: &str) -> bool {
        self.broad_patterns.iter().any(|p| p == rule)
    }
}

// --- Helpers ---

fn resolve_list(defaults: &[&str], list_config: &ListConfig) -> Vec<String> {
    match list_config.mode {
        ListMode::Replace => list_config.items.clone(),
        ListMode::Extend => {
            let mut v: Vec<String> = defaults.iter().map(|s| s.to_string()).collect();
            v.extend(list_config.items.iter().cloned());
            v
        }
    }
}

/// Extract the command pattern from a Bash() rule, stripping the trailing :*
fn extract_bash_pattern(rule: &str) -> Option<&str> {
    if !rule.starts_with("Bash(") || !rule.ends_with(')') {
        return None;
    }
    let inner = &rule[5..rule.len() - 1];
    // Strip trailing :* if present
    Some(inner.strip_suffix(":*").unwrap_or(inner))
}

/// Returns true if the command starts with a shell env var assignment (e.g. `FOO=bar cmd`).
fn starts_with_env_var(cmd: &str) -> bool {
    let bytes = cmd.as_bytes();
    let mut i = 0;
    if i >= bytes.len() || !(bytes[i].is_ascii_uppercase() || bytes[i] == b'_') {
        return false;
    }
    i += 1;
    while i < bytes.len() && (bytes[i].is_ascii_uppercase() || bytes[i].is_ascii_digit() || bytes[i] == b'_') {
        i += 1;
    }
    i < bytes.len() && bytes[i] == b'='
}

/// Check if a command matches any prefix in the given list.
fn matches_command_list(cmd: &str, list: &[String]) -> bool {
    list.iter().any(|prefix| {
        cmd == prefix.as_str()
            || cmd.starts_with(&format!("{prefix} "))
            || cmd.starts_with(&format!("{prefix}:"))
    })
}

/// Simple glob matching: `*` matches any sequence of non-empty chars.
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.is_empty() {
        return true;
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
        } else {
            match text[pos..].find(part) {
                Some(found) => {
                    if found == 0 {
                        return false;
                    }
                    pos += found + part.len();
                }
                None => return false,
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Rules {
        Rules::default()
    }

    // --- Deny list tests ---

    #[test]
    fn deny_rm() {
        let r = rules();
        assert!(r.matches_deny_list("rm -rf /tmp"));
        assert!(r.matches_deny_list("rm -r /tmp"));
        assert!(r.matches_deny_list("rm /tmp/file"));
        assert!(r.matches_deny_list("rm -f /tmp/file"));
    }

    #[test]
    fn deny_cd_and() {
        let r = rules();
        assert!(r.matches_deny_list("cd && git status"));
        assert!(r.matches_deny_list("cd /tmp && rm -rf ."));
    }

    #[test]
    fn deny_git_tag_delete() {
        let r = rules();
        assert!(r.matches_deny_list("git tag -d v1.0"));
    }

    #[test]
    fn allow_safe_commands() {
        let r = rules();
        assert!(!r.matches_deny_list("ls -la"));
        assert!(!r.matches_deny_list("git status"));
        assert!(!r.matches_deny_list("cargo build"));
    }

    #[test]
    fn replace_deny_list_removes_defaults() {
        use crate::config::{Config, ListConfig, ListMode};
        let mut config = Config::default();
        config.deny_patterns = ListConfig {
            mode: ListMode::Replace,
            items: vec!["shutdown".to_string()],
        };
        let r = Rules::from_config(&config);
        // rm should no longer be denied
        assert!(!r.matches_deny_list("rm /tmp/file"));
        // custom pattern should be denied
        assert!(r.matches_deny_list("shutdown now"));
    }

    #[test]
    fn extend_deny_list_adds_to_defaults() {
        use crate::config::{Config, ListConfig, ListMode};
        let mut config = Config::default();
        config.deny_patterns = ListConfig {
            mode: ListMode::Extend,
            items: vec!["shutdown".to_string()],
        };
        let r = Rules::from_config(&config);
        // Original patterns still apply
        assert!(r.matches_deny_list("rm /tmp/file"));
        // Custom pattern also applies
        assert!(r.matches_deny_list("shutdown now"));
    }

    // --- Rule classification tests ---

    #[test]
    fn classify_safe_bash() {
        let r = rules();
        assert_eq!(r.classify_rule("Bash(ls:*)"), RiskTier::Safe);
        assert_eq!(r.classify_rule("Bash(git status:*)"), RiskTier::Safe);
        assert_eq!(r.classify_rule("Bash(git diff:*)"), RiskTier::Safe);
        assert_eq!(r.classify_rule("Bash(tree:*)"), RiskTier::Safe);
        assert_eq!(r.classify_rule("Bash(cat:*)"), RiskTier::Safe);
    }

    #[test]
    fn classify_moderate_bash() {
        let r = rules();
        assert_eq!(r.classify_rule("Bash(git commit:*)"), RiskTier::Moderate);
        assert_eq!(r.classify_rule("Bash(git push:*)"), RiskTier::Moderate);
        assert_eq!(r.classify_rule("Bash(cargo:*)"), RiskTier::Moderate);
        assert_eq!(r.classify_rule("Bash(mkdir:*)"), RiskTier::Moderate);
    }

    #[test]
    fn classify_dangerous_bash() {
        let r = rules();
        assert_eq!(r.classify_rule("Bash(sudo rm:*)"), RiskTier::Dangerous);
        assert_eq!(r.classify_rule("Bash(sudo apt install:*)"), RiskTier::Dangerous);
    }

    #[test]
    fn classify_file_tools() {
        let r = rules();
        assert_eq!(r.classify_rule("Edit(src/**/*.rs)"), RiskTier::Moderate);
        assert_eq!(r.classify_rule("Write(docs/**/*.md)"), RiskTier::Moderate);
        assert_eq!(r.classify_rule("Read(**/*.yml)"), RiskTier::Safe);
    }

    #[test]
    fn classify_web_tools() {
        let r = rules();
        assert_eq!(r.classify_rule("WebFetch(domain:docs.rs)"), RiskTier::Safe);
        assert_eq!(r.classify_rule("WebSearch"), RiskTier::Safe);
    }

    #[test]
    fn classify_skill() {
        let r = rules();
        assert_eq!(r.classify_rule("Skill(rust-cli-coder)"), RiskTier::Safe);
    }

    #[test]
    fn classify_mcp_read() {
        let r = rules();
        assert_eq!(r.classify_rule("mcp__atlassian__getJiraIssue"), RiskTier::Moderate);
    }

    #[test]
    fn classify_mcp_write() {
        let r = rules();
        assert_eq!(
            r.classify_rule("mcp__slack__conversations_add_message"),
            RiskTier::Dangerous
        );
    }

    // --- Tool input classification tests ---

    #[test]
    fn classify_input_bash_safe() {
        let r = rules();
        assert_eq!(r.classify_tool_input("Bash", "ls -la"), RiskTier::Safe);
        assert_eq!(r.classify_tool_input("Bash", "git log --oneline"), RiskTier::Safe);
    }

    #[test]
    fn classify_input_bash_dangerous() {
        let r = rules();
        assert_eq!(r.classify_tool_input("Bash", "sudo rm -rf /"), RiskTier::Dangerous);
        assert_eq!(r.classify_tool_input("Bash", "rm -rf /tmp"), RiskTier::Dangerous);
    }

    #[test]
    fn classify_input_force_push() {
        let r = rules();
        assert_eq!(
            r.classify_tool_input("Bash", "git push --force origin main"),
            RiskTier::Dangerous
        );
    }

    // --- Recommendation tests ---

    #[test]
    fn recommend_promote_safe_local() {
        let r = rules();
        assert_eq!(r.recommend(RiskTier::Safe, "local", "Bash(ls:*)"), Recommendation::Promote);
    }

    #[test]
    fn recommend_keep_moderate_local() {
        let r = rules();
        assert_eq!(r.recommend(RiskTier::Moderate, "local", "Bash(cargo:*)"), Recommendation::Keep);
    }

    #[test]
    fn recommend_remove_dangerous_local() {
        let r = rules();
        assert_eq!(
            r.recommend(RiskTier::Dangerous, "local", "Bash(sudo rm:*)"),
            Recommendation::Remove
        );
    }

    #[test]
    fn recommend_deny_pattern() {
        let r = rules();
        assert_eq!(
            r.recommend(RiskTier::Dangerous, "local", "Bash(rm -rf:*)"),
            Recommendation::Deny
        );
    }

    #[test]
    fn recommend_narrow_broad() {
        let r = rules();
        assert_eq!(
            r.recommend(RiskTier::Moderate, "global", "Bash(git:*)"),
            Recommendation::Narrow
        );
    }

    // --- Overly broad tests ---

    #[test]
    fn broad_git_pattern() {
        let r = rules();
        assert!(r.is_overly_broad("Bash(git:*)"));
    }

    #[test]
    fn not_broad_specific_git() {
        let r = rules();
        assert!(!r.is_overly_broad("Bash(git status:*)"));
    }

    // --- Env var prefix tests ---

    #[test]
    fn env_var_prefix_is_dangerous() {
        let r = rules();
        assert_eq!(
            r.classify_rule("Bash(GH_TOKEN=\"$TOKEN\" gh pr view:*)"),
            RiskTier::Dangerous
        );
        assert_eq!(
            r.classify_rule("Bash(GIT_SSH_COMMAND=\"ssh -i ~/.ssh/id\" git push:*)"),
            RiskTier::Dangerous
        );
        assert_eq!(r.classify_rule("Bash(API_KEY=\"abc\" curl:*)"), RiskTier::Dangerous);
    }

    #[test]
    fn lowercase_var_is_not_env_var() {
        let r = rules();
        assert_ne!(r.classify_rule("Bash(foo=bar cmd:*)"), RiskTier::Dangerous);
    }

    #[test]
    fn starts_with_env_var_fn() {
        assert!(starts_with_env_var("GH_TOKEN=\"x\" cmd"));
        assert!(starts_with_env_var("GIT_SSH_COMMAND=ssh git"));
        assert!(starts_with_env_var("_VAR=1 cmd"));
        assert!(!starts_with_env_var("git status"));
        assert!(!starts_with_env_var("gh pr view"));
    }

    // --- git -C tests ---

    #[test]
    fn git_dash_c_is_dangerous() {
        let r = rules();
        assert_eq!(r.classify_rule("Bash(git -C /some/path push:*)"), RiskTier::Dangerous);
        assert_eq!(r.classify_rule("Bash(git -C ~/repos/foo status:*)"), RiskTier::Dangerous);
    }

    #[test]
    fn git_without_dash_c_not_affected() {
        let r = rules();
        assert_eq!(r.classify_rule("Bash(git status:*)"), RiskTier::Safe);
        assert_eq!(r.classify_rule("Bash(git push:*)"), RiskTier::Moderate);
    }

    // --- bash -c tests ---

    #[test]
    fn bash_dash_c_is_dangerous() {
        let r = rules();
        assert_eq!(r.classify_rule("Bash(bash -c 'echo hi':*)"), RiskTier::Dangerous);
        assert_eq!(r.classify_rule("Bash(bash -c:*)"), RiskTier::Dangerous);
    }

    // --- subsumes tests ---

    #[test]
    fn subsumes_bash_prefix() {
        assert!(subsumes("Bash(git:*)", "Bash(git status:*)"));
        assert!(!subsumes("Bash(git status:*)", "Bash(git:*)"));
    }

    #[test]
    fn subsumes_file_tool() {
        assert!(subsumes("Edit(**)", "Edit(**/*.rs)"));
        assert!(!subsumes("Edit(**/*.rs)", "Edit(**)"));
    }

    #[test]
    fn subsumes_same_rule() {
        assert!(!subsumes("Bash(git:*)", "Bash(git:*)"));
    }
}
