use serde::Serialize;
use std::fmt;

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
}

impl fmt::Display for Recommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Recommendation::Promote => "promote",
            Recommendation::Keep => "keep",
            Recommendation::Narrow => "narrow",
            Recommendation::Remove => "remove",
            Recommendation::Deny => "deny",
        })
    }
}

/// Patterns that should always be denied.
const PERMANENT_DENY: &[&str] = &[
    "git tag -d",
    "git push * :refs/tags/",
    "git push * --delete * tag",
    "rm -rf",
    "rm -r ",
    "cd &&",
];

/// Check if a command matches any permanent deny pattern.
pub fn matches_deny_list(command: &str) -> bool {
    let cmd = command.trim();
    PERMANENT_DENY.iter().any(|pattern| {
        if pattern.contains('*') {
            glob_match(pattern, cmd)
        } else if *pattern == "cd &&" {
            // Special case: "cd && ..." or "cd <path> && ..."
            cmd.starts_with("cd ") && cmd.contains("&&")
        } else {
            cmd.starts_with(pattern)
        }
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
            // First part must match at start
            if !text[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
        } else {
            // Subsequent parts must appear after previous match
            match text[pos..].find(part) {
                Some(found) => {
                    // Ensure at least one char was consumed by the wildcard
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

/// MCP tools that perform write/mutation operations.
const MCP_WRITE_PREFIXES: &[&str] = &[
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

/// Read-only Bash commands (first word or "first second" prefix).
const SAFE_BASH_COMMANDS: &[&str] = &[
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

/// Moderate Bash commands (local writes, reversible).
const MODERATE_BASH_COMMANDS: &[&str] = &[
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
    "rkvr rmrf",
    "gh pr create",
    "curl",
];

/// Classify a permission rule string like "Bash(git status:*)" or "Edit(src/**/*.rs)".
pub fn classify_rule(rule: &str) -> RiskTier {
    // Parse the rule format: Tool(pattern) or bare tool name
    if let Some(inner) = extract_bash_pattern(rule) {
        return classify_bash_command(inner);
    }

    if rule.starts_with("Edit(") || rule.starts_with("Write(") {
        return RiskTier::Moderate;
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
        return classify_mcp_tool(rule);
    }

    // Unknown tool type - default to moderate
    RiskTier::Moderate
}

/// Classify a raw tool invocation (tool_name + tool_input).
pub fn classify_tool_input(tool_name: &str, normalized_input: &str) -> RiskTier {
    match tool_name {
        "Bash" => classify_bash_command(normalized_input),
        "Edit" | "Write" => RiskTier::Moderate,
        "Read" | "Glob" | "Grep" => RiskTier::Safe,
        "WebFetch" | "WebSearch" => RiskTier::Safe,
        name if name.starts_with("mcp__") => classify_mcp_tool(name),
        _ => RiskTier::Moderate,
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

fn classify_bash_command(cmd: &str) -> RiskTier {
    let cmd = cmd.trim();

    // Check permanent deny list first
    if matches_deny_list(cmd) {
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

    // Check safe commands (longest prefix match)
    if matches_command_list(cmd, SAFE_BASH_COMMANDS) {
        return RiskTier::Safe;
    }

    // Check moderate commands
    if matches_command_list(cmd, MODERATE_BASH_COMMANDS) {
        return RiskTier::Moderate;
    }

    // Unknown command - default to moderate
    RiskTier::Moderate
}

fn classify_mcp_tool(tool: &str) -> RiskTier {
    // Strip any pattern suffix for matching
    let base = tool.split('(').next().unwrap_or(tool);
    if MCP_WRITE_PREFIXES.iter().any(|prefix| base.starts_with(prefix)) {
        RiskTier::Dangerous
    } else {
        RiskTier::Moderate
    }
}

/// Check if a command matches any prefix in the given list.
fn matches_command_list(cmd: &str, list: &[&str]) -> bool {
    list.iter().any(|prefix| {
        cmd == *prefix || cmd.starts_with(&format!("{prefix} ")) || cmd.starts_with(&format!("{prefix}:"))
    })
}

/// Determine recommendation for a rule given its risk tier and source.
pub fn recommend(tier: RiskTier, source: &str, rule: &str) -> Recommendation {
    // Permanently denied patterns
    if let Some(cmd) = extract_bash_pattern(rule)
        && matches_deny_list(cmd)
    {
        return Recommendation::Deny;
    }

    // Overly broad patterns
    if is_overly_broad(rule) {
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

/// Check if a rule pattern is overly broad (covers both safe and dangerous commands).
fn is_overly_broad(rule: &str) -> bool {
    // Bash(git:*) would match git status (safe) AND git push --force (dangerous)
    let broad_patterns = ["Bash(git:*)", "Bash(docker:*)", "Bash(sudo:*)", "Bash(yes:*)"];
    broad_patterns.contains(&rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Deny list tests ---

    #[test]
    fn deny_rm_rf() {
        assert!(matches_deny_list("rm -rf /tmp"));
        assert!(matches_deny_list("rm -rf"));
    }

    #[test]
    fn deny_rm_r() {
        assert!(matches_deny_list("rm -r /tmp"));
    }

    #[test]
    fn deny_cd_and() {
        assert!(matches_deny_list("cd && git status"));
        assert!(matches_deny_list("cd /tmp && rm -rf ."));
    }

    #[test]
    fn deny_git_tag_delete() {
        assert!(matches_deny_list("git tag -d v1.0"));
    }

    #[test]
    fn allow_safe_commands() {
        assert!(!matches_deny_list("ls -la"));
        assert!(!matches_deny_list("git status"));
        assert!(!matches_deny_list("cargo build"));
    }

    // --- Rule classification tests ---

    #[test]
    fn classify_safe_bash() {
        assert_eq!(classify_rule("Bash(ls:*)"), RiskTier::Safe);
        assert_eq!(classify_rule("Bash(git status:*)"), RiskTier::Safe);
        assert_eq!(classify_rule("Bash(git diff:*)"), RiskTier::Safe);
        assert_eq!(classify_rule("Bash(tree:*)"), RiskTier::Safe);
        assert_eq!(classify_rule("Bash(cat:*)"), RiskTier::Safe);
    }

    #[test]
    fn classify_moderate_bash() {
        assert_eq!(classify_rule("Bash(git commit:*)"), RiskTier::Moderate);
        assert_eq!(classify_rule("Bash(git push:*)"), RiskTier::Moderate);
        assert_eq!(classify_rule("Bash(cargo:*)"), RiskTier::Moderate);
        assert_eq!(classify_rule("Bash(mkdir:*)"), RiskTier::Moderate);
    }

    #[test]
    fn classify_dangerous_bash() {
        assert_eq!(classify_rule("Bash(sudo rm:*)"), RiskTier::Dangerous);
        assert_eq!(classify_rule("Bash(sudo apt install:*)"), RiskTier::Dangerous);
    }

    #[test]
    fn classify_file_tools() {
        assert_eq!(classify_rule("Edit(src/**/*.rs)"), RiskTier::Moderate);
        assert_eq!(classify_rule("Write(docs/**/*.md)"), RiskTier::Moderate);
        assert_eq!(classify_rule("Read(**/*.yml)"), RiskTier::Safe);
    }

    #[test]
    fn classify_web_tools() {
        assert_eq!(classify_rule("WebFetch(domain:docs.rs)"), RiskTier::Safe);
        assert_eq!(classify_rule("WebSearch"), RiskTier::Safe);
    }

    #[test]
    fn classify_skill() {
        assert_eq!(classify_rule("Skill(rust-cli-coder)"), RiskTier::Safe);
    }

    #[test]
    fn classify_mcp_read() {
        assert_eq!(classify_rule("mcp__atlassian__getJiraIssue"), RiskTier::Moderate);
    }

    #[test]
    fn classify_mcp_write() {
        assert_eq!(
            classify_rule("mcp__slack__conversations_add_message"),
            RiskTier::Dangerous
        );
    }

    // --- Tool input classification tests ---

    #[test]
    fn classify_input_bash_safe() {
        assert_eq!(classify_tool_input("Bash", "ls -la"), RiskTier::Safe);
        assert_eq!(classify_tool_input("Bash", "git log --oneline"), RiskTier::Safe);
    }

    #[test]
    fn classify_input_bash_dangerous() {
        assert_eq!(classify_tool_input("Bash", "sudo rm -rf /"), RiskTier::Dangerous);
        assert_eq!(classify_tool_input("Bash", "rm -rf /tmp"), RiskTier::Dangerous);
    }

    #[test]
    fn classify_input_force_push() {
        assert_eq!(
            classify_tool_input("Bash", "git push --force origin main"),
            RiskTier::Dangerous
        );
    }

    // --- Recommendation tests ---

    #[test]
    fn recommend_promote_safe_local() {
        assert_eq!(
            recommend(RiskTier::Safe, "local", "Bash(ls:*)"),
            Recommendation::Promote
        );
    }

    #[test]
    fn recommend_keep_moderate_local() {
        assert_eq!(
            recommend(RiskTier::Moderate, "local", "Bash(cargo:*)"),
            Recommendation::Keep
        );
    }

    #[test]
    fn recommend_remove_dangerous_local() {
        assert_eq!(
            recommend(RiskTier::Dangerous, "local", "Bash(sudo rm:*)"),
            Recommendation::Remove
        );
    }

    #[test]
    fn recommend_deny_pattern() {
        assert_eq!(
            recommend(RiskTier::Dangerous, "local", "Bash(rm -rf:*)"),
            Recommendation::Deny
        );
    }

    #[test]
    fn recommend_narrow_broad() {
        assert_eq!(
            recommend(RiskTier::Moderate, "global", "Bash(git:*)"),
            Recommendation::Narrow
        );
    }

    // --- Overly broad tests ---

    #[test]
    fn broad_git_pattern() {
        assert!(is_overly_broad("Bash(git:*)"));
    }

    #[test]
    fn not_broad_specific_git() {
        assert!(!is_overly_broad("Bash(git status:*)"));
    }
}
