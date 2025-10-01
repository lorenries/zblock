# Zblock — Product Requirements Document (PRD)

**Owner:** You (with AI agent support)
**Date:** 2025-10-01
**Product name:** `zblock`
**Platform:** macOS (Apple Silicon + Intel), CLI-first
**Primary goal:** Provide a _hard-to-bypass_ website blocker for focused work sessions, implemented in Zig as a learning project.

---

## 1) Summary

`zblock` is a macOS CLI that blocks access to configurable domains for fixed windows of time. It achieves robustness by enforcing packet-level rules via **pf** anchors (not `/etc/hosts`) and by optionally **locking down DNS** paths. Enforcement persists across reboots during an active session and is supervised by a root daemon. The tool is intentionally frictionful to disable mid-session, providing deterrence for highly technical users.

---

## 2) Success criteria & KPIs

**MVP acceptance (functional):**

- Blocking a list of domains prevents access by domain and by direct IP (v4+v6) for the session duration.
- Changing system DNS servers does not bypass during a session.
- Browser built-in DoH/DoT does not bypass for a curated set of popular resolvers.
- Rebooting the Mac during a session keeps the block active until the timer expires.
- Attempting to disable pf is countered by the daemon within ≤10 seconds.

**Quality / UX metrics:**

- Start command completes in ≤3s for ≤200 domains.
- No network instability for non-target traffic (false positives < 1%).
- Clear, human-readable `zblock status`.

**Engineering KPIs:**

- Unit test coverage ≥ 70% for domain resolution + table generation logic.
- Black-box test suite for pf rule application and rollback.
- One-command install/uninstall with idempotent behavior.

---

## 3) Out of scope (MVP)

- GUI.
- Cross-platform support (Linux nftables, Windows WFP).
- Per-app blocking and process attribution.
- Parental-control-grade tamper resistance (SIP changes, recovery OS).
- NetworkExtension / System Extension implementation.

---

## 4) Users & use cases

- **Primary:** Developers / knowledge workers seeking distraction-free windows.
- **Secondary:** Habit builders who want friction to override urges but don’t require enterprise lockdown.

Use cases:

- “Block social media for 45 minutes.”
- “Study mode every weekday 9–12.”
- “Focus mode: default-deny except allowlist (optional profile).”

---

## 5) Threat model (practical)

**Assumptions:** user has admin privileges and physical access. Absolute prevention is impossible. Target is _deterrence + delay_.

**Likely bypass attempts & counters:**

- Change DNS → Block :53 outbound during session (or force-redirect if local resolver later).
- Use DoH/DoT → Block :853 and curated DoH IP ranges; drop QUIC where applicable.
- Access via direct IP → Resolve domains to IPs (A/AAAA) and block those tables.
- Kill pf → Launchd daemon re-enables pf and reloads anchor continuously while active.
- Reboot → Daemon reapplies on boot until end-time.

---

## 6) Feature requirements

### 6.1 CLI commands (MVP)

- `zblock init`
  - Installs launchd daemon (`zblockd`), creates pf anchor template, verifies pf availability, sets directories.

- `zblock add <domains...> [--group <name>]`
  - Adds domains to `config.json`; normalizes and dedupes; supports groups (default: `default`).

- `zblock list [--group <name>]`
  - Prints groups and domains; supports JSON output with `--json`.

- `zblock start --for <duration>|--until <iso>` `[--group <name>]` `[--dns-lockdown]`
  - Requests daemon to begin a session; daemon resolves targets, writes tables, enables pf, loads anchor, and starts refresh loop.

- `zblock status`
  - Shows active window, remaining time, pf state, rules/anchors loaded, current tables (counts), daemon health.

- `zblock uninstall`
  - Removes daemon/anchor only when no active session; leaves user data unless `--purge`.

### 6.2 Enforcement rules (pf anchor)

- Tables: `<zblock_v4>`, `<zblock_v6>` with file-backed lists in `/var/db/zblock`.
- Block outbound to those tables for all protocols.
- DNS lockdown mode: block outbound TCP/UDP 53; block TCP 853 (DoT); optional `<zblock_doh>` table drop on 443/853.
- utun interfaces: block outbound on active `utun*` during session to hinder VPNs (best-effort).

### 6.3 Resolution & refresh

- Resolve A/AAAA for all domains at session start and every 10 minutes (configurable), with timeout/backoff.
- Respect per-domain TTL caps (e.g., min 60s, max 600s) to limit churn.
- Atomic table updates with `pfctl -T replace`.

### 6.4 Persistence & recovery

- On boot, daemon checks `active.json`; if end-time > now → re-enforce.
- If pf disabled or anchor unloaded while active → re-enable within 10s.
- Clean rollback when session ends; restore pf prior state if `zblock` enabled it.

### 6.5 Observability

- Logs to `/var/log/zblock/{daemon.log,actions.log}` (rotated).
- `zblock status --json` for scripting.

---

## 7) Non-functional requirements

- Zig 0.13+; reproducible builds; cross-compiled universal binary (arm64 + x86_64 via `lipo`).
- No panics for expected failures; clear exit codes.
- All file writes atomic (write temp + rename).
- Daemon memory footprint < 25MB idle; CPU near 0% between refresh cycles.

---

## 8) System design

### 8.1 Components

- **CLI (`zblock`)** — unprivileged; communicates with daemon over a root-owned Unix domain socket at `/var/run/zblockd.sock`.
- **Daemon (`zblockd`)** — root; installed via launchd; enforces sessions, manages pf, performs resolution.
- **On-disk state**
  - User config: `~/.config/zblock/config.json`.
  - Daemon state: `/var/db/zblock/active.json`, `/var/db/zblock/blocked_v4.table`, `/var/db/zblock/blocked_v6.table`, `/var/db/zblock/doh.table` (optional).
  - PF anchor: `/etc/pf.anchors/zblock` (template).

### 8.2 Data model (JSON)

```json
// config.json
{
  "groups": {
    "default": ["twitter.com", "youtube.com"],
    "social": ["reddit.com", "instagram.com"]
  }
}
```

```json
// active.json
{
  "group": "social",
  "start_epoch": 1696166400,
  "end_epoch": 1696169100,
  "dns_lockdown": true,
  "pf_was_enabled": false,
  "last_apply_checksum": "sha256:..."
}
```

### 8.3 IPC schema

- Socket messages are JSON frames with an `op` field: `start`, `status`, `ping`.
- Daemon replies with `{ ok: bool, error?: string, data?: any }`.

### 8.4 PF anchor template (generated once)

```
table <zblock_v4> persist file "/var/db/zblock/blocked_v4.table"
table <zblock_v6> persist file "/var/db/zblock/blocked_v6.table"

# Optional DoH IPs table
# table <zblock_doh> persist file "/var/db/zblock/doh.table"

# DNS lockdown (enabled by daemon when requested)
# block out quick proto { udp tcp } from any to any port 53
# block out quick proto tcp from any to any port 853
# block out quick proto { udp tcp } from any to <zblock_doh> port { 443 853 }

# Block targets (v4 + v6)
block out quick from any to <zblock_v4>
block out quick from any to <zblock_v6>
```

---

## 9) Security & privacy

- Root daemon runs with least privileges possible; no network listeners (local socket only).
- Config and state files have restrictive permissions (`600` for JSON, `644` for tables, owned by root where appropriate).
- Logs exclude domain lists by default; include only counts & hashes unless `--verbose-logging`.
- Emergency-unblock requires admin auth (macOS Authorization Services) and adds a 60s enforced delay.

---

## 10) AI agent plan (how the agent starts building)

### 10.1 Repository layout

```
/ (repo root)
  README.md
  LICENSE
  .github/workflows/ci.yml
  build.zig
  src/
    main_cli.zig
    daemon.zig
    pf.zig          // pfctl wrappers, table IO
    dns.zig         // resolver & TTL handling
    ipc.zig         // Unix socket protocol
    fs.zig          // atomic writes, paths
    log.zig
  assets/
    launchd/com.zblock.daemon.plist.tmpl
    pf/zblock.anchor.tmpl
  test/
    dns_test.zig
    pf_table_test.zig
    ipc_test.zig
  scripts/
    package.sh      // codesign/notarize hooks (later)
```

### 10.2 First milestones for the agent

1. **Bootstrap project**
   - Initialize Zig project, `build.zig`, `README` with usage.
   - Implement `zblock list/add` reading/writing `config.json`.

2. **pf integration (dry-run)**
   - Generate anchor from template; `pfctl -nf` syntax check; no enforcement yet.
   - Implement table file writers.

3. **Daemon + IPC**
   - Launchd plist generation; daemon main loop listening on `/var/run/zblockd.sock`.
   - Implement `status` and health checks.

4. **Resolution loop**
   - Async A/AAAA resolution; write tables atomically; checksum state.

5. **Enforcement**
   - Enable pf if disabled; load anchor; `-T replace` tables; DNS lockdown flags.
   - Re-apply if pf off/anchor missing.

6. **Session lifecycle**
   - Start flows; on-boot restoration; logging.

7. **Tests & packaging**
   - Unit tests; integration tests using a simulated ruleset (mock `pfctl` binary for CI).
   - Brew formula draft (later).

### 10.3 Agent task backlog (atomic, verifiable steps)

- T-001: Create `paths` module that resolves per-user and system paths; unit tests.
- T-002: Implement `config.json` schema + JSON (de)serialization; dedupe + normalization (punycode, lowercasing).
- T-003: Write anchor template to `/etc/pf.anchors/zblock`; add `pfctl -nf` dry-run step; return diagnostics.
- T-004: Implement `pfctl` wrapper with `-T replace` and error mapping → structured codes.
- T-005: Implement resolver with timeouts, parallelism, and min/max TTL caps.
- T-006: Implement daemon `start` op: compute end-time, write `active.json`, apply rules.
- T-007: Implement watchdog that re-enables pf when active every 5–10s.
- T-008: Implement `status` op returning JSON.
- T-010: Add utun interface detection and temporary block rules during session.
- T-011: Add DNS lockdown switches and DoH table support.

### 10.4 Prompting & guardrails for the agent

- **Coding style:** idiomatic Zig; no panics; propagate errors using `!Error` pattern; prefer `std.mem.Allocator` use consistency.
- **Security guardrails:** never run privileged actions from CLI; only via daemon.
- **Testing:** mock `pfctl` calls behind an interface; CI uses the mock by default.

### 10.5 Definition of done (DOD) for MVP

- All acceptance criteria in §2 satisfied on macOS 13–15.
- `zblock` installed and functional via `sudo zblock init` and tested with a standard domain set.
- README includes threat model and rollback instructions.

---

## 11) User experience details

### 11.1 CLI output examples

```
$ zblock start --for 45m --group social --dns-lockdown
Starting focus session until 2025-10-01T16:45:00-04:00
• Resolved 132 A/AAAA records (v4: 98, v6: 34)
• DNS lockdown: enabled (53/853 blocked)
• pf anchor loaded: zblock (2 tables)
✅ Blocking active. Stay focused!
```

```
$ zblock status --json
{
  "active": true,
  "until": "2025-10-01T16:45:00-04:00",
  "tables": { "v4": 98, "v6": 34 },
  "dns_lockdown": true,
  "pf_enabled": true,
  "watchdog_uptime_sec": 600
}
```

### 11.2 Errors

- If pf syntax invalid → show `pfctl -nf` stderr and abort.
- If not root when required → clear message: “This action requires the zblock daemon (root). Run `zblock init` and try again.”

---

## 12) Installation & packaging

- `zblock init` performs:
  1. Copy daemon binary to `/usr/local/libexec/zblockd` (root:wheel 755).
  2. Write `/Library/LaunchDaemons/com.zblock.daemon.plist` (root:wheel 644); bootstrap with `launchctl`.
  3. Write `/etc/pf.anchors/zblock` and validate.
  4. Create `/var/db/zblock` and `/var/log/zblock` (root-owned).

- Optional: brew formula later; codesign/notarization planned but not required for local dev.

---

## 13) Test plan

- **Unit:** domain normalization; resolver timeout/backoff; atomic writes; IPC framing.
- **Integration (local):** start flows on a test host; verify `curl` to blocked domains and direct IPs fails; verify DNS changes don’t help; verify pf auto re-enable after manual `pfctl -d`.
- **Reboot tests:** active session survives reboot; end-time honored.
- **Regression:** table replace is atomic; partial writes never leave pf in inconsistent state.

---

## 14) Risks & mitigations

- **pf changes across macOS versions:** keep anchor minimal; rely on `pfctl` CLI instead of `/dev/pf` ioctls initially.
- **DoH list completeness:** treat as best-effort; ship a curated baseline and allow user append.
- **False positives (shared IPs/CDNs):** offer `--strict-ip` flag to require domain+SNI (future NE path).

---

_End of PRD_
