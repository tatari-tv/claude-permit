# claude-permit

Rust CLI that logs every Claude Code tool invocation, classifies permission rules by risk tier, and produces actionable recommendations to tighten your security posture.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/tatari-tv/claude-permit/main/install.sh | bash
```

Installs to `~/.local/bin` by default. Override with `INSTALL_DIR`:

```bash
INSTALL_DIR=/usr/local/bin curl -fsSL https://raw.githubusercontent.com/tatari-tv/claude-permit/main/install.sh | bash
```

### From Source

```bash
cargo install --git https://github.com/tatari-tv/claude-permit
```

---

## Updating

After the first install, subsequent upgrades go through the built-in `update` subcommand, backed by the [`renew`](https://github.com/tatari-tv/renew) library:

```bash
claude-permit update              # check whether a newer release is available (default action)
claude-permit update check        # explicit check (exit 0 = current, 1 = update available, 2 = error)
claude-permit update install      # download latest, verify sha256, atomic-replace this binary
claude-permit update install --yes
claude-permit update revert       # restore the previous version from the backup slot
```

`update install` writes a backup of the current binary to `~/.local/share/claude-permit/<install-path-hash>/backup/` before swapping. `revert` restores it. Only the most recent prior version is retained.

When `claude-permit` is invoked interactively (any subcommand other than `log`/`check`) and a newer release exists, a one-line stderr notice is printed. The `log` hook hot path is exempt from this entirely - no cache reads, no network probes.

**Caveats:**

- **Source installs:** users who installed via `cargo install --git ...` or `cargo install --path .` should keep updating that way. `claude-permit update install` swaps the binary in place but does not refresh cargo's `~/.cargo/.crates.toml` registry.
- **Do not pass an explicit `VERSION`** to `update install`. Renew v0.1.2 has a known bug where `install_version` queries `/releases/latest` and rejects mismatches, so `claude-permit update install 0.1.5` fails unless `0.1.5` is also the latest tag. Omit the positional argument to install latest.

---

## Problem

Claude Code accumulates permission rules over time through one-off approvals during sessions. These rules live in `settings.json` and `settings.local.json` with no built-in way to review, prune, or promote them. After a few weeks of use, you end up with hundreds of rules - some dangerously broad, some stale, some duplicated - and no feedback loop between your permission decisions and your permission policy.

You can't answer basic questions: Which rules are never used? Which one-off approvals keep recurring and should be permanent? Which rules are dangerously broad? Are any rules violating safety policies (e.g., allowing `rm -rf` instead of a safe alternative)?

---

## Setup

### 1. Register the hook

```bash
claude-permit install --yes
```

This adds `claude-permit log` to the `PreToolUse` hooks in `~/.claude/settings.json`. Or add it manually:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          { "type": "command", "command": "claude-permit log" }
        ]
      }
    ]
  }
}
```

### 2. Verify

```bash
claude-permit check
```

Confirms the SQLite database is writable, the hook is registered, and the binary is in PATH.

### 3. Use Claude Code normally

Every tool invocation is silently logged to a local SQLite database (`~/.local/share/claude-permit/events.db`) with timestamp, session ID, tool name, normalized input, and risk tier. The hook completes in under 50ms and never blocks your session.

---

## Commands

### audit

Reads `settings.json` and `settings.local.json`, classifies every rule by risk tier, checks against the deny list, and outputs a recommendation for each rule.

```bash
# Show all rules
claude-permit audit

# Filter by pattern (exact -> prefix -> substring cascade)
claude-permit audit docker
claude-permit audit git cargo
claude-permit audit "Bash(git status:*)"

# Filter by risk tier (cannot combine with --apply)
claude-permit audit --risk dangerous
claude-permit audit --risk moderate

# Apply all actionable recommendations and write changes
claude-permit audit --apply

# Apply specific actions only
claude-permit audit --apply promote
claude-permit audit --apply remove dupe
claude-permit audit --apply promote remove deny dupe

# Combine pattern filter with apply
claude-permit audit docker --apply
claude-permit audit git --apply remove

# Change output format
claude-permit audit --format json
claude-permit audit --format markdown
```

**Pattern filtering** uses a cascading match: tries exact first, then prefix, then substring. Returns the first non-empty result set. No patterns returns everything.

`--apply` actions:

| Action | What it does |
| --- | --- |
| `promote` | Moves safe rules from local to global settings |
| `remove` | Deletes dangerous rules from local settings |
| `deny` | Removes deny-list violations from allow lists |
| `dupe` | Removes rules covered by a broader rule |

`--apply` with no action words applies all four. `--apply` and `--risk` are mutually exclusive - use pattern filtering to narrow scope before applying.

**Recommendation column values:**

| Value | Meaning |
| --- | --- |
| `keep` | Rule is fine where it is |
| `promote` | Safe rule in local - move to global |
| `narrow` | Pattern is too broad - tighten it manually |
| `remove` | Dangerous rule - delete it |
| `deny` | Matches a permanent deny pattern - remove from allow list |
| `dupe` | Covered by a broader rule - redundant |

---

### suggest

Queries the event database for patterns you've approved repeatedly across multiple sessions and recommends promoting them to permanent allow rules.

```bash
# Show all suggestions
claude-permit suggest

# Filter by pattern
claude-permit suggest git
claude-permit suggest Bash

# Tune thresholds
claude-permit suggest --threshold 5 --sessions 3

# Change output format
claude-permit suggest --format json
claude-permit suggest --format markdown
```

Default thresholds: 3+ observations, 2+ distinct sessions. Only tools that aren't internal Claude mechanics (TaskCreate, SendMessage, Agent, etc.) are surfaced.

---

### report

Session summary of permission activity - event counts by risk tier, top tools used, and a list of any dangerous events.

```bash
claude-permit report              # latest session
claude-permit report --session <id>
claude-permit report --format json
```

---

### clean

Prune old events from the database.

```bash
claude-permit clean                    # delete events older than 90 days
claude-permit clean --older-than 30
claude-permit clean --dry-run          # preview without deleting
```

---

### check

Verify hook installation and database connectivity. Exits non-zero if anything is misconfigured.

```bash
claude-permit check
```

---

### install

Add the PreToolUse hook to `~/.claude/settings.json`. Dry-run by default.

```bash
claude-permit install          # preview - shows what would be added
claude-permit install --yes    # write changes
```

Skips silently if the hook is already registered.

---

## Risk Tiers

| Tier | Examples |
| --- | --- |
| **Safe** | `Bash(git status:*)`, `Bash(ls:*)`, `Read(**/*.rs)`, `WebSearch` |
| **Moderate** | `Bash(git push:*)`, `Bash(cargo:*)`, `Edit(**/*.rs)`, `Read(**)` |
| **Dangerous** | `Bash(sudo:*)`, `Bash(rm -rf:*)`, `Edit(**)`, `Write(**)` |

**Notes:**

- `Read(**)` (bare or wildcard) is **Moderate** - carte blanche filesystem read access
- `Read(**/*.rs)` with a specific path pattern is **Safe**
- `Edit(**)` and `Write(**)` are **Dangerous** - unrestricted write access

### Permanent Deny Patterns

These are blocked at hook time (when `enforce-deny: true`) and flagged in audit regardless:

- `git tag -d` - local tag deletion
- `git push * :refs/tags/` - remote tag deletion via refspec
- `git push * --delete * tag` - remote tag deletion via `--delete`
- `rm -rf` and `rm -r ` - recursive removal (dangerous, permanently denied)
- `cd && ` - compound cd with `&&`

### Automatic Dangerous Rule Detection

The following patterns are classified **Dangerous** regardless of command and flagged for removal:

- **Environment variable assignments** - `GH_TOKEN="..." gh pr view`, `GIT_SSH_COMMAND="..." git push` - one-time invocations that shouldn't be permanent allow rules
- `git -C <path>` - path-locked git operations specific to a single invocation context
- `bash -c` - arbitrary shell escapes

Clean these up with `claude-permit audit --apply remove`.

---

## Configuration

`~/.config/claude-permit/claude-permit.yml`:

```yaml
suggest-threshold: 3      # min observations to trigger a suggestion
suggest-sessions: 2       # min distinct sessions
clean-older-than: 90      # days before cleanup eligibility
enforce-deny: true        # block dangerous patterns at hook level (not just audit)
pager: less -R            # pager command (omit to disable paging)
# extra-deny-patterns:
#   - "shutdown"
#   - "reboot"
# risk-overrides:
#   "cargo build": "safe"
```

The pager activates only when output exceeds terminal height. Short results print directly.

With `enforce-deny: true`, the hook blocks dangerous commands at invocation time and returns an error to Claude before the command runs.

---

## Tips

- **Start with audit now** - Run `claude-permit audit` before enabling the hook. It reads your existing settings files and will surface surprises immediately.
- **Filter before applying** - Use pattern args to narrow scope: `claude-permit audit docker --apply` only touches docker rules.
- `audit` is your preview - Running `audit` without `--apply` is the dry run. What you see is exactly what `--apply` will act on.
- **Promote recurring approvals** - If `suggest` keeps recommending the same patterns, promote them. Fewer prompts, no loss of security.
- **Dupe cleanup is safe** - `--apply dupe` removes rules already covered by a broader rule. It cannot break anything.
- **The hook is non-blocking** - It outputs passthrough JSON and completes in under 50ms. It never slows down your Claude Code sessions.
