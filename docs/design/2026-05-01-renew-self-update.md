# Design Document: Self-Update via `renew`

**Author:** Scott Idler
**Date:** 2026-05-01
**Status:** Implemented (pending Phase 4 shakedown against post-bump release)
**Review Passes Completed:** 5/5

## Summary

Wire the `renew` library (v0.1.2) into `claude-permit` so users can discover and install new releases from inside the tool itself. Add an `update` subcommand and a passive "newer version available" stderr notice on interactive invocations. The `log` hook hot path is exempted from all renew machinery to preserve PreToolUse latency.

## Problem Statement

### Background

`claude-permit` ships via two paths today:

1. `install.sh` -- clones the repo and runs `cargo install --path .`.
2. Tagged GitHub releases with prebuilt tarballs for `linux-amd64`, `linux-arm64`, `macos-x86_64`, `macos-arm64` (produced by `.github/workflows/release-and-publish.yml`).

There is no in-tool mechanism to (a) tell the user a newer release exists or (b) install it. Users must re-run `install.sh` or download a tarball by hand.

This is one of three Tatari CLIs (`ccu`, `claude-permit`, `persona-cli`) shipped in the same week (2026-04-03) with a roughly weekly release cadence. The friction of "go re-clone and rebuild" multiplies across users x tools x weeks.

### Problem

Users have no in-tool path to discover or install `claude-permit` updates. We should adopt the standard Tatari CLI self-update mechanism: the `renew` library.

### Goals

- Add a `claude-permit update` subcommand that exposes `check`, `install`, and `revert`.
- Print a passive stderr notice when a newer version is available and stderr is a TTY.
- Do not regress `claude-permit log` or `claude-permit check` hot-path latency, and do not pollute `log` stdout.
- Reuse the existing release workflow (which already conforms to the renew producer contract).

### Non-Goals

- **No automatic install.** Notice on interactive runs only; install is opt-in via `update install`.
- **No background refresh daemon.** Cache lives at `dirs::cache_dir()/claude-permit/` and refreshes on demand.
- **No release-workflow changes.** The current workflow already emits compliant artifacts; verifying is the work, not rebuilding.
- **No replacement of `install.sh`.** First-time install still goes through `install.sh` or `cargo install --path .`. `renew` is for subsequent upgrades.

## Proposed Solution

### Overview

Add `renew = { git = "https://github.com/tatari-tv/renew", tag = "v0.1.2" }` to `Cargo.toml`, set `[package].repository`, add an `Update(UpdateCmd)` variant to the CLI enum, and wire the `Renew` instance into `main.rs` after the hot-path gate (which exempts `Log` and `Check`).

### Architecture

```rust
fn run() -> Result<()> {
    setup_logging()?;
    let cli = Cli::parse();

    // Three classes of command:
    //   - Hot path (Log, Check): never construct renew.
    //   - Update: construct renew (we'll need it for dispatch) but skip the
    //     passive notice -- the subcommand prints its own version-availability
    //     output, and running notify here would duplicate it.
    //   - Everything else: construct + notify.
    let renew_handle = match &cli.command {
        Command::Log | Command::Check => None,
        Command::Update(_) => Some(renew::renew!().expect("repository metadata")),
        _ => {
            let r = renew::renew!().expect("repository metadata");
            r.notify_if_outdated();   // stderr-TTY-gated; may hit GitHub API on stale cache
            Some(r)
        }
    };

    match cli.command {
        Command::Log => { /* existing log arm, unchanged */ }
        Command::Check => { /* existing check arm, unchanged */ }
        Command::Update(cmd) => {
            let r = renew_handle.expect("renew constructed for non-hot-path commands");
            std::process::exit(cmd.run(&r));
        }
        // all other existing arms unchanged
    }

    Ok(())
}
```

The first match (`match &cli.command`) borrows `cli.command` to peek at the variant; the second match (`match cli.command`) consumes it. This pattern compiles cleanly because the borrow is released at the end of the first match's scope before the second match takes ownership.

**The hot-path gate is the central design decision** and departs from the renew README quickstart (which calls `notify_if_outdated()` before `Cli::parse()`). Two reasons:

1. **`notify_if_outdated()` is not free.** Reading `renew/src/renew.rs`: the function checks `std::io::stderr().is_terminal()`, then calls `check_latest()`, which honors the cache but performs a synchronous blocking GitHub API request (default network timeout 5s) whenever the cache is absent or older than `cache_ttl` (default 24 hours, per `DEFAULT_CACHE_TTL_SECS` at `renew/src/renew.rs:15`). Hot-path commands cannot afford a potential 5s blocking call.
2. **`claude-permit log`** runs as a `PreToolUse` hook on every Claude Code tool use; **`claude-permit check`** is invoked from health-check scripts (e.g., from `~/.claude/`) and may have a TTY stderr. Both should bypass renew entirely so neither pays cache IO nor risks an outbound network probe.

The stderr-TTY gate inside `notify_if_outdated()` is correct for a release-mode hook (Claude Code pipes hook stderr), but it is fragile in development -- a user debugging a hook with `2>/dev/tty` would unwittingly trigger a network probe inside the hot path. The explicit gate makes the safety invariant load-bearing in this repo, not in renew.

### Data Model

No new types defined in this repo. Public surface used from `renew`:

- `renew::Renew` -- handle, constructed via the `renew::renew!()` macro.
- `renew::UpdateCmd` -- `clap::Args` struct exposing `check` / `install` / `revert`.
- `renew::Result` / `renew::Error` -- for any direct calls (none planned beyond `UpdateCmd::run`).

The `renew!()` macro expands to `Renew::new(env!("CARGO_PKG_REPOSITORY"), env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))`. It requires `[package].repository` to be set in `Cargo.toml`.

### API Design

New CLI subcommand. The full surface comes from `renew::UpdateCmd` (a `clap::Args`) -- we are inheriting its flags, not redefining them. Exit code semantics below come from the renew README's exit-code table; we treat that as authoritative for the consumer:

```
claude-permit update                                   # default = check (no args)
claude-permit update check  [--refresh]                # exit 0 = up to date, 1 = update available, 2 = error
claude-permit update install [VERSION] [--yes] [--force] [--refresh] [--install-path PATH]
                                                       # exit 0 = installed or aborted by user, 2 = error
claude-permit update revert  [--yes] [--install-path PATH]
                                                       # exit 0 = reverted or aborted by user,  2 = error
```

Behavior notes:

- `install` downloads the platform tarball, verifies the sha256 sidecar, and atomic-replaces the running binary. A backup of the current binary is written to `dirs::data_local_dir()/claude-permit/<install-path-hash>/backup/` before swap.
- `revert` restores from that backup. There is exactly one backup slot per install path, so two consecutive `install` calls overwrite the first backup; revert can only restore the most recent prior version, not arbitrary history.
- Confirmation prompts default to `N`. If stdin is not a TTY and `--yes` was not passed, the prompt errors with `PromptRequiredButStdinNotTty` and exits 2 -- this is the documented behavior we want for piped invocations.
- A user typing `N` (or anything not `y` / `yes`) at the prompt exits cleanly with code 0.
- **Known bug -- positional `VERSION`:** `claude-permit update install 0.1.5` will fail unless `0.1.5` is also the latest tag. Internally `Renew::install_version` queries `/releases/latest` and rejects mismatches. This bug is in renew v0.1.2 and is upstream (not in our control). Workaround: omit the positional to install latest. We document this in the user-facing notes (Phase 5) but cannot remove the flag without forking the type.

### Implementation Plan

#### Phase 1: Cargo metadata
**Model:** sonnet

- Add `repository = "https://github.com/tatari-tv/claude-permit"` to `[package]` in `Cargo.toml`.
- Add `renew = { git = "https://github.com/tatari-tv/renew", tag = "v0.1.2" }` to `[dependencies]` (use `cargo add` so the lockfile updates cleanly).
- Run `cargo check` to confirm the dep resolves and the macro can read `CARGO_PKG_REPOSITORY` at compile time.

#### Phase 2: CLI wiring
**Model:** sonnet

- Add `Update(renew::UpdateCmd)` variant to `Command` in `src/cli.rs`. Include a one-line doc comment so `--help` lists it.
- In `src/main.rs::run()`, restructure as shown in [Architecture](#architecture):
  - Move `Command::Log` and `Command::Check` arms into an early-return block before `renew!()` is called.
  - After the gate, construct `let r = renew::renew!().expect("repository metadata");` and call `r.notify_if_outdated();`.
  - Dispatch `Command::Update(cmd) => std::process::exit(cmd.run(&r))`.
- Keep all other subcommand arms unchanged.
- Verify the existing `main()` `is_log` special-case (which prints `{}` and swallows errors when `log` fails) still triggers correctly by checking `std::env::args().nth(1) == Some("log")`. `Update` errors must NOT route through this path -- they go through the standard `eprintln + exit(1)` flow.

#### Phase 3: Verify release workflow
**Model:** sonnet

- Re-read `.github/workflows/release-and-publish.yml` and confirm:
  - Tarball name matches `claude-permit-<tag>-<platform>.tar.gz` for `linux-amd64`, `linux-arm64`, `macos-x86_64`, `macos-arm64`.
  - Sidecar name matches `<tarball>.sha256` and contains the lowercase-hex sha256 in the first 64 chars.
  - Tarball contains exactly one regular file (the `claude-permit` binary) -- check the `tar -czvf ... -C artifacts claude-permit` invocation.
  - Tag pattern is `v*` (annotated, on `main`).
- No expected changes -- this phase produces a single line in the PR description: "release workflow verified compliant, no changes."

#### Phase 4: Shakedown the new binary
**Model:** sonnet

Cut a release with phases 1+2, install it on a real machine, then run `/cli-shakedown` against the freshly built binary. The skill systematically exercises every command and flag and produces a field guide of tested examples; that's the broad coverage. Beyond what shakedown discovers automatically, three integration-flavored checks must be exercised explicitly because they touch state the binary alone can't observe (the live release, the backup directory, and the hook hot path):

- `update install --yes` against an older binary, then `claude-permit --version` reflects the new tag and `claude-permit log < hook-fixture.json 2>/dev/null` still emits valid JSON. This is the post-replace end-to-end check -- catches the case where install "succeeds" but the new binary segfaults or is the wrong platform.
- `update revert --yes` after the above, then `claude-permit --version` confirms the previous tag is restored.
- `claude-permit log < hook-fixture.json 2>/dev/null` -- stdout is exactly the expected JSON, no `notify_if_outdated` notice leaks in. This is the hot-path-silence invariant; shakedown won't catch it on its own because shakedown runs interactively (stderr is a TTY) where the notice IS expected.

#### Phase 5: User-facing docs
**Model:** sonnet

- Add an "Updating" section to `README.md` pointing at `claude-permit update install`. Include the `cargo install --path .` caveat for source installs and the "do not pass an explicit VERSION" note (positional version arg has the renew v0.1.2 install_version bug).
- Update `install.sh` comment header noting that first install still uses the script, but subsequent updates go through `claude-permit update install`.
- Update `cli.rs` `after_help` to mention `claude-permit update --help`.

## Alternatives Considered

### Alternative 1: Reinstall via `install.sh` only

- **Description:** Document the existing path; print a stderr message at startup telling users to re-run `install.sh`.
- **Pros:** Zero new dependencies; nothing to maintain.
- **Cons:** Requires a clean clone + cargo build for every update; no version-check mechanism; no atomic swap or revert; bad UX at three CLIs x weekly cadence.
- **Why not chosen:** The whole point of standardizing on `renew` across all three Tatari CLIs is to stop paying this UX tax.

### Alternative 2: Hand-rolled self-update

- **Description:** Custom `claude-permit update` command that calls the GitHub API, downloads the tarball, verifies sha256, swaps the binary.
- **Pros:** No new external dep; tailor behavior precisely.
- **Cons:** Reinvents `renew`. Error-prone bits (atomic replace, backup/revert, sha verification, redirect-auth stripping) are exactly what `renew` already solves. Three CLIs each maintaining their own copy is worse.
- **Why not chosen:** Maintenance cost dwarfs the dependency cost.

### Alternative 3: Call `notify_if_outdated()` before parsing args (per renew README)

- **Description:** Match the renew quickstart pattern verbatim -- run notify before `Cli::parse()`.
- **Pros:** One fewer code branch; matches the README example exactly.
- **Cons:** On the `claude-permit log` hook hot path, every PreToolUse invocation would do at minimum a TTY check on stderr; if a developer ever runs the hook with `2>/dev/tty` for debugging, the notice path would do a cache read AND, if the cache is stale, a synchronous GitHub API round-trip on every tool use.
- **Why not chosen:** Hook-path latency and reliability are non-negotiable. The match-on-`Command` gate adds ~5 lines of code to make the safety property load-bearing in this repo, not contingent on internal renew behavior.

## Technical Considerations

### Dependencies

- **External:** `renew` v0.1.2 (git dep, pinned to annotated tag, NOT a branch).
- **Internal:** none new.
- **Transitive (added by renew):** `flate2`, `tar`, `sha2`, `self-replace`, `semver`, `ureq` with rustls. All standard, no surprises.
- **No `tracing-log` bridge required:** claude-permit uses `log` + `env_logger` (per `Cargo.toml`), and renew also emits `log` records, so they share a backend. The bridge is only needed for consumers using `tracing`.

### Performance

- **Hot path (`Command::Log`, `Command::Check`):** unchanged. `renew!()` is never constructed and `notify_if_outdated()` is never called.
- **`Command::Update`:** `renew!()` is constructed but `notify_if_outdated()` is skipped (the subcommand has its own output; running notify would print version-availability twice, once to stderr and once to stdout via `cmd.run`).
- **Interactive paths (`audit`, `suggest`, `report`, `install`, `apply`):** `notify_if_outdated()` runs.
  - **Cache hit** (entry exists and is younger than `cache_ttl`, default 24 hours per `renew/src/renew.rs:15`): one cache-file read at `dirs::cache_dir()/claude-permit/check.yml`. ~ms.
  - **Cache miss / stale** AND stderr is a TTY: synchronous blocking GitHub API request inside `check_latest()`, network timeout 5s. With the 24h default TTL, a given machine hits this at most once per day -- but on a slow network or during a GitHub incident, that one invocation per day blocks for up to 5s before the user's actual command starts. Lock file at `dirs::cache_dir()/claude-permit/check.lock` serializes concurrent processes; the loser falls back to whatever cache exists.
  - **Cache miss / stale** AND stderr is NOT a TTY: function returns immediately before any IO -- the TTY gate is the first thing checked.
- `update check` (explicit) always honors the cache; `update install` does the network call regardless.

### Security

- Auth: anonymous works for public repos; `claude-permit` is public, so no token required by default. If made private, set `GH_TOKEN` or `GITHUB_TOKEN` in env.
- The auth header is stripped on the 302 redirect to S3 by `renew` itself (`RedirectAuthHeaders::Never`); no token leakage to presigned URLs.
- All downloads are sha256-verified against the sidecar before replacement.
- Self-replace is atomic; failed verification or download leaves the existing binary intact.

### Testing Strategy

- No new unit tests in `claude-permit` -- the `renew` library has its own coverage of cache, network, sha verification, and self-replace.
- `/cli-shakedown` covers broad command/flag exercise on the new binary.
- Phase 4 explicit checks cover the three things shakedown can't: post-replace version-reflects-new-tag, revert restores prior tag, and hot-path silence on the `log` invocation (where stderr is NOT a TTY).
- Optional follow-up (not blocking): add an integration test in `tests/` that invokes `claude-permit log < fixture.json`, asserts exit code 0, asserts stdout parses as JSON, and asserts stdout has no trailing bytes after the JSON. Such a test would also catch any future regression where `notify_if_outdated()` silently leaks bytes into stdout.

### Rollout Plan

1. Implement phases 1-3 on a feature branch.
2. Open a PR per `tatari-tv/*` branch-protection convention (verify live state with `gh api repos/tatari-tv/claude-permit/branches/main/protection`; if 404, direct push is acceptable, but PR is preferred for the visibility of this change).
3. After merge, on `main`: `bump` (patch) then push the tag. The tag triggers `release-and-publish.yml`.
4. Phase 4 manual smoke runs against the published release on lappy + desk.
5. Phase 5 docs and `#clipboard` announcement.
6. **Soak constraint:** do not bump renew's pinned tag (e.g., to v0.1.3) inside `claude-permit` until `ccu` (the canary consumer) has run for at least a week on the new tag without issue. Cross-consumer renew bumps go consumer-by-consumer, never as a sweep, so a regression in renew doesn't take down all three Tatari CLIs simultaneously.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| `notify_if_outdated()` leaks output into `claude-permit log` stdout, breaking the hook | Low | High | Hot-path gate (`Log` bypasses renew entirely); phase 4 verifies stdout cleanliness |
| Hot-path latency regression on `log` or `check` | Low | High | Hot-path gate; even cache-only IO is avoided. Critical because `notify_if_outdated()` is NOT IO-free on stale cache |
| Network probe on hook hot path during user debugging (`2>/dev/tty`) | Low | High | Hot-path gate -- the stderr-TTY check inside renew is bypassed entirely for `Log` |
| macOS Gatekeeper blocks atomic self-replace on unsigned binaries | Med | Med | renew v0.1.2 backs up before replacing; `revert` restores; users can fall back to `install.sh` |
| User runs `cargo install --path .` then later `update install` -- cargo's `~/.cargo/.crates.toml` registry no longer reflects the installed binary version | High | Low | Document in README: users who installed from source should continue to update via `cargo install --path .` from the latest tag, not via `claude-permit update install` |
| `Renew::install_version` known bug (only accepts version equal to `latest`) | N/A | N/A | Use `UpdateCmd::Install { version: None, .. }` via the dispatch only; never call `install_version` directly |
| Network failure during `update check` blocks interactive flow | Low | Low | `check` returns exit 2 on error; users can retry; cache is stale-tolerant |
| Concurrent `claude-permit` processes refresh cache simultaneously | Low | Low | renew uses an exclusive lock at `dirs::cache_dir()/claude-permit/check.lock`; loser falls through to existing cache |
| User passes positional `VERSION` to `update install`, hits the renew v0.1.2 install_version bug | Med | Low | Document in README + `--help`; pinning renew to a tag means we'll get the upstream fix when it lands and can bump deliberately after canary soak |
| `claude-permit update install --yes` running concurrently with `claude-permit log` (active hook on a Claude Code session) | Med | Low | `self-replace` is designed for this -- the running process keeps its file handle; new invocations get the new binary. No coordination needed |

## Resolved During Review

- **`notify_if_outdated()` IO behavior** (Pass 2): NOT IO-free on stale cache. Confirmed by reading `renew/src/renew.rs` lines 15, 116-134 (`check_latest`), and 361-377 (`notify_if_outdated`). It performs a synchronous blocking GitHub API request whenever the cache is older than `cache_ttl` (default 24h, `DEFAULT_CACHE_TTL_SECS`) AND stderr is a TTY. Resolution: hot-path gate covers `Command::Log` and `Command::Check`.
- **Duplicate version-available output on `update check`** (Architect review): `notify_if_outdated()` printing to stderr and `UpdateCmd::Check` printing to stdout would render the same message twice on `claude-permit update check` with stale cache. Resolution: `Command::Update(_)` constructs `Renew` (needed for dispatch) but skips `notify_if_outdated()`; the subcommand owns its own output.
- **Cache TTL was 24h, not 1h** (Architect review, verified at `renew/src/renew.rs:15`): doc previously claimed default was 1h. Corrected throughout. The 24h default makes GitHub rate-limit concerns essentially moot at any realistic Tatari user count.
- **Synchronous network I/O at startup is acceptable** (Architect review, consensus after pushback): `notify_if_outdated()` can block up to 5s on cache miss + slow network. Architect's initial position was "never block on self-update." After pushback citing (a) industry-standard pattern (`gh`, `npm`, `brew`, `cargo`, `rustup` all do this), (b) the verified 24h TTL bounding worst case to 1x 5s/day per machine, (c) renew v0.1.2 has no async path so backgrounding would require forking the library, and (d) a `--no-update-check` flag can be added reactively if reports come in -- consensus was to document the trade-off honestly in the Performance section and proceed. If real-world reports surface, the right fix lives in renew (e.g., a `RENEW_NO_UPDATE_CHECK=1` opt-out), not in claude-permit.

## Open Questions

- [ ] **`update install` from `~/.cargo/bin/claude-permit`:** users who installed via `cargo install --path .` will silently desync cargo's `~/.cargo/.crates.toml` registry if they then run `update install`. Current mitigation is documentation only. Should we add a path-prefix check (`current_exe()` contains `.cargo/bin`) and either (a) refuse with a helpful error, or (b) print a louder warning before invoking renew's prompt? Option (a) is paternalistic and the heuristic is brittle (CARGO_INSTALL_ROOT, symlinks, custom layouts). Option (b) is non-trivial because the prompt is owned by `UpdateCmd::Install`, not us -- we'd need to print our own warning before calling `cmd.run(&r)`. Defer until smoke testing reveals real-world impact; if no Tatari user reports the issue, leave as docs-only.

## References

- `renew` README: https://github.com/tatari-tv/renew
- `renew` v0.1.2 tag: https://github.com/tatari-tv/renew/releases/tag/v0.1.2
- `renew/src/renew.rs` -- `check_latest` (lines 116-134) and `notify_if_outdated` (lines 361-377), the implementations behind the IO-behavior decision
- `renew/src/cmd.rs` -- `UpdateCmd` definition, including the inherited `--refresh` / `--force` / positional `VERSION` flags
- claude-permit release workflow: `.github/workflows/release-and-publish.yml`
- Sibling design docs: `2026-03-24-claude-permit.md` (initial scaffold), `2026-03-24-apply.md` (apply subcommand)
