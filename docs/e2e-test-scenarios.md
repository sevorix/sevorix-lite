# End-to-End Test Scenarios for Sevorix Watchtower

These scenarios exercise the product as a real user would — starting the daemon, sending requests, checking verdicts, using the dashboard, managing integrations, etc. They are not unit tests; each scenario validates a complete user-observable outcome.

Each scenario should:
1. **Set up** — start the daemon with specific policies/roles as needed
2. **Act** — perform the user action (HTTP request, CLI command, etc.)
3. **Assert** — verify the response, log entries, WebSocket events, and side effects
4. **Tear down** — stop the daemon, clean up temporary policy files

Tests should use a dedicated test policy directory (not the user's real `~/.sevorix/`) to avoid interference. The daemon should bind to a randomized port to allow parallel test execution.

---

## 1. Proxy Mode — Core Traffic Flow

### 1.1 Safe HTTP request passes through transparently
Start daemon. Configure an upstream HTTP server. Proxy a benign GET request (e.g., `GET https://httpbin.org/get`) through the Watchtower proxy. Verify the response body is returned unmodified, status code matches upstream, and a GREEN event appears in the traffic log.

### 1.2 Blocked request returns 403
Proxy a POST request whose body contains `DROP TABLE users`. Verify the proxy returns HTTP 403, the response body contains a block reason, and a RED lane event is logged.

### 1.3 Flagged request triggers hold-and-wait for operator review
Proxy a request whose body matches a Flag policy (e.g., `SELECT * FROM admin_users`). Verify the proxy holds the connection open, broadcasts a PENDING WebSocket event, and does NOT immediately forward or block. After the operator approves via the dashboard, verify the request is forwarded and the response returned to the caller.

### 1.4 HTTPS CONNECT tunneling
Configure the proxy and issue an HTTPS request via CONNECT. Verify the tunnel is established, data flows bidirectionally, and a GREEN CONNECT event is broadcast.

### 1.5 Large payload handling
Proxy a request with a body exceeding 2000 characters. Verify the payload is truncated in the log/event but the full body is forwarded upstream.

### 1.6 Empty body handling
Proxy a POST request with no body. Verify it is treated as GREEN and forwarded without error.

### 1.7 Multiple concurrent requests
Send 10+ simultaneous proxy requests (mix of safe, blocked, flagged). Verify all return correct verdicts without race conditions or dropped connections.

---

## 2. Analyze API (`POST /analyze`)

### 2.1 Block verdict for dangerous command
POST `{"payload": "DROP TABLE users", "context": "Shell"}`. Verify response `status` is `BLOCK`, `lane` is `RED`, and `latency_ms` is near 0.

### 2.2 Allow verdict for safe command
POST `{"payload": "ls -la", "context": "Shell"}`. Verify `status` is `ALLOW`, `lane` is `GREEN`.

### 2.3 Flag verdict triggers hold-and-wait in analyze
POST `{"payload": "SELECT * FROM admin_users", "context": "Shell"}` (matching a Flag policy). Verify the response is not returned immediately — the call blocks until an operator decision is made (or the timeout fires). After the operator approves, verify `status` is `FLAG`, `lane` is `YELLOW`.

### 2.4 Context-scoped policy — Shell policy does not trigger on Network context
Create a policy with `context: "Shell"`. POST `{"payload": "<matching text>", "context": "Network"}`. Verify verdict is ALLOW (policy is scoped to Shell only).

### 2.5 Context-scoped policy — Network policy triggers on Network context
Create a policy with `context: "Network"`. POST `{"payload": "<matching text>", "context": "Network"}`. Verify verdict is BLOCK.

### 2.6 "All" context policy applies everywhere
Create a policy with `context: "All"`. Verify it triggers on both Shell and Network contexts.

### 2.7 Role-scoped evaluation
Create two roles (`admin`, `readonly`) with different policy sets. Verify the same payload yields different verdicts depending on the `role` field.

### 2.8 Missing/invalid fields
POST with missing `payload` field. Verify a sensible error response (not a 500).

### 2.9 Agent ID tracking
POST with `agent: "test-bot"`. Verify the agent ID appears in the logged event and WebSocket broadcast.

---

## 3. Human-in-the-Loop Intervention (YELLOW Lane)

### 3.1 Proxy — flagged request held, operator allows
Proxy a request matching a Flag policy. Verify: (a) connection held open, (b) PENDING WebSocket event broadcast with event UUID, payload, reason, and configurable timeout countdown. Operator clicks Allow in dashboard. Verify: (c) request forwarded to upstream, (d) DECIDED WebSocket event broadcast, (e) event logged as YELLOW ALLOW.

### 3.2 Proxy — flagged request held, operator blocks
Same setup. Operator clicks Block. Verify: (a) 403 returned to caller, (b) DECIDED event broadcast, (c) event logged as YELLOW BLOCK.

### 3.3 Proxy — operator pauses countdown, then allows
Operator clicks Pause before the countdown expires. Verify: (a) PAUSED WebSocket event broadcast, (b) countdown freezes — no automatic block fires. Operator clicks Resume then Allow. Verify request is forwarded.

### 3.4 Proxy — timeout expires with default block action
Configure `timeout_action: "block"` in `~/.sevorix/settings.json`. Set a short `timeout_secs` (e.g., 5). Proxy a flagged request and do not act on the dashboard. Verify: (a) after 5s the request returns 403, (b) event logged as timeout-block.

### 3.5 Proxy — timeout expires with allow action
Configure `timeout_action: "allow"`. Same flow. Verify: (a) request forwarded after timeout, (b) event logged as timeout-allow.

### 3.6 Shell channel (`/analyze`) — held and decided
POST a flagged payload to `/analyze`. Verify the HTTP call blocks. Operator approves via `POST /api/decide`. Verify the `/analyze` response is returned with the operator's verdict.

### 3.7 Shell channel — pause via `/api/pause`
POST a flagged payload to `/analyze`. `POST /api/pause` with `paused: true`. Verify countdown freezes. `POST /api/pause` with `paused: false`. Verify countdown resumes.

### 3.8 Invalid event_id on `/api/decide`
POST to `/api/decide` with an unknown event_id. Verify a 404 or appropriate error (not a 500).

### 3.9 Intervention does not apply to RED lane
Proxy a request matching a Block policy. Verify it is rejected immediately without creating a pending decision entry.

### 3.10 Configurable timeout via settings.json
Set `timeout_secs: 10` in `~/.sevorix/settings.json`. Start daemon. Proxy a flagged request. Verify dashboard countdown starts at 10s.

---

## 4. Policy Engine — Match Types

### 4.1 Simple (substring) matching — case-sensitive
Create a Simple policy for `DROP TABLE`. Verify `DROP TABLE` triggers it, but `drop table` does NOT (case-sensitive).

### 4.2 Regex matching
Create a Regex policy for `\b\d{3}-\d{2}-\d{4}\b` (SSN pattern). Verify `123-45-6789` triggers it, but `12345-6789` does not.

### 4.3 Executable matching
Create an Executable policy pointing to a script that exits 0 for certain input. Verify exit-code-0 input is blocked and exit-code-1 input is allowed.

### 4.4 Invalid regex graceful handling
Create a policy with an invalid regex pattern. Verify the engine loads without crashing, and the policy doesn't match anything (fails open for that policy).

### 4.5 Multiple policies — Block takes precedence over Flag
Load multiple policies where both a Block and a Flag match the same text. Verify the Block takes precedence (RED lane, not YELLOW).

### 4.6 Kill flag propagation
Create a policy with `kill: true`. Verify the kill flag is included in the scan result/event for downstream handling.

### 4.7 Policy hot-reload
Start the daemon. Add a new policy file to `~/.sevorix/policies/`. Call `POST /api/policies/reload`. Verify the new policy takes effect without restarting the daemon.

---

## 5. Role System

### 5.1 Role with subset of policies
Create a role that references only 2 of 5 loaded policies. Verify only those 2 policies are evaluated when the role is specified.

### 5.2 Unknown role fails closed (BLOCK)
Send an analyze request with a role name that doesn't exist. Verify the response is BLOCK (fail-closed — not ALLOW) since the role is unresolvable.

### 5.3 No role configured — fail closed
Start the daemon with no `default_role` set and no active session role. Send a request. Verify it is BLOCKED (fail-closed).

### 5.4 Default role set in SevshSettings — seeded at startup
Configure `default_role: "analyst"` in SevshSettings. Start daemon. Verify all requests without an explicit role are evaluated against the `analyst` role's policies.

### 5.5 `sevorix start` fails if default_role is unknown
Configure `default_role: "nonexistent"`. Run `sevorix start`. Verify the daemon refuses to start and returns an error identifying the unknown role.

### 5.6 `sevorix session set-role` updates active role
With daemon running, run `sevorix session set-role analyst`. Verify subsequent requests are evaluated against `analyst` policies. Role field appears in traffic log events.

### 5.7 `sevorix session set-role` rejects unknown role
Run `sevorix session set-role unknown-role`. Verify the command receives an HTTP 400 and the active role is unchanged.

### 5.8 Role field in traffic log events
Trigger BLOCK, ALLOW, and PENDING events. Read the JSONL log. Verify each entry contains a `"role"` field matching the active session role.

### 5.9 Role filtering at startup
Start the daemon with `--roles admin,readonly`. Verify only those roles' policies are loaded and other policies are excluded.

### 5.10 Role file loading — single and array formats
Place both a single-role JSON and a multi-role JSON array in `~/.sevorix/roles/`. Verify all roles are loaded correctly.

---

## 6. WebSocket Live Feed

### 6.1 Event received on analyze (ALLOW/BLOCK)
Connect a WebSocket client to `/ws`. POST to `/analyze` with a non-flagged payload. Verify the WebSocket receives a JSON event with correct verdict, lane, payload, timestamp.

### 6.2 Event received on proxy block
Connect WebSocket. Proxy a blocked request. Verify the event appears on the WebSocket.

### 6.3 PENDING event broadcast on flagged request
Connect WebSocket. Proxy a flagged request. Verify a PENDING event is broadcast containing: event_id, payload preview, reason, layer, countdown timeout.

### 6.4 DECIDED event broadcast after operator decision
After receiving PENDING, POST to `/api/decide`. Verify a DECIDED event is broadcast with the operator's verdict.

### 6.5 PAUSED event broadcast on pause/resume
POST to `/api/pause` with `paused: true`. Verify PAUSED event broadcast. POST with `paused: false`. Verify another event (PAUSED or RESUMED) is broadcast.

### 6.6 Multiple subscribers
Connect 3 WebSocket clients. Trigger an event. Verify all 3 receive the same event.

### 6.7 Subscriber disconnect — no server crash
Connect and disconnect a WebSocket rapidly while events are being generated. Verify the server continues operating normally.

### 6.8 Late subscriber — no backlog flood
Connect a WebSocket after 100 events have already been broadcast. Verify the client does not receive historical events (only new ones).

---

## 7. Dashboard & REST APIs

### 7.1 Dashboard serves static HTML
GET `/dashboard/desktop.html`. Verify 200 OK and HTML content.

### 7.2 Dashboard redirect
GET `/dashboard`. Verify redirect to `/dashboard/desktop.html`.

### 7.3 Event history — pagination
Generate 100+ events. GET `/api/events?page=1&limit=50`. Verify 50 results. GET page 2. Verify the next batch with no overlap.

### 7.4 Event history — layer filter
Generate events across shell/network/syscall layers. GET `/api/events?layer=shell`. Verify only shell events returned.

### 7.5 Event history — search filter
Generate events. GET `/api/events?search=DROP`. Verify only events containing "DROP" are returned.

### 7.6 Event history — session filter
Run two daemon sessions. Query events with the first session's UUID. Verify only events from that session are returned.

### 7.7 Stats endpoint
Generate a mix of BLOCK/FLAG/ALLOW events. GET `/api/stats`. Verify counts and averages are accurate.

### 7.8 Sessions endpoint
Run multiple sessions (start/stop daemon twice). GET `/api/sessions`. Verify both sessions are listed.

### 7.9 Health endpoint
GET `/health`. Verify 200 OK.

### 7.10 Version endpoint
GET `/api/version`. Verify it returns edition info (Lite vs Pro).

### 7.11 Intervention panel appears for YELLOW event
With the dashboard open, proxy a flagged request. Verify a yellow overlay panel appears showing: payload preview, reason, layer badge, and countdown timer. Verify Allow and Block buttons are present, and a Pause button is available.

### 7.12 Allow button forwards request
Click Allow on the intervention panel. Verify the panel disappears, the request is forwarded, and the event appears in the history as YELLOW ALLOW.

### 7.13 Block button rejects request
Click Block. Verify the panel disappears, 403 is returned to the caller, and the event appears as YELLOW BLOCK.

### 7.14 Countdown visual — red pulse at ≤5s
Let the countdown run to ≤5 seconds. Verify the timer turns red and pulses as specified.

### 7.15 Force-terminate and forensic report buttons not present
Verify that the dashboard does NOT show "Force Terminate Agent" or "Open Forensic Report" buttons (removed features).

---

## 8. CLI Commands

### 8.1 Start / Status / Stop lifecycle with rich startup output
`sevorix start` — verify PID file created, daemon running. Verify startup output includes: Watchtower PID, eBPF daemon PID (if enabled), session ID, service log path, session log path, traffic log path, and dashboard URL.
`sevorix status` — verify shows "running" with correct PID.
`sevorix stop` — verify PID file removed, process terminated.
`sevorix status` — verify shows "not running".

### 8.2 Run in foreground
`sevorix run` — verify server starts on port 3000, responds to requests, and Ctrl-C terminates cleanly.

### 8.3 Restart
`sevorix restart` — verify old daemon stops, new one starts with new PID.

### 8.4 Double start prevention
`sevorix start` twice. Verify second invocation returns an error (already running).

### 8.5 Stop when not running
`sevorix stop` when no daemon is running. Verify graceful error message.

### 8.6 Validate command
`sevorix validate "DROP TABLE users" -r admin -C Shell`. Verify output shows BLOCK verdict and exit code != 0.
`sevorix validate "ls -la" -C Shell`. Verify ALLOW and exit code 0.

### 8.7 Config check
`sevorix config check` with valid policies. Verify it reports policy count, role count, no errors.
`sevorix config check` with a malformed policy file. Verify it reports the error clearly.

### 8.8 `sevorix session set-role` — valid role
With daemon running and a known role loaded, run `sevorix session set-role <known-role>`. Verify success and that subsequent requests are evaluated under that role.

### 8.9 `sevorix session set-role` — unknown role rejected
Run `sevorix session set-role bogus`. Verify the command outputs a clear error (HTTP 400 from server) and the session role is unchanged.

---

## 9. Integrations

### 9.1 Claude Code integration — install (prerequisite check only)
Start daemon, ensure sevsh is installed. Run `sevorix integrations install claude-code` (or alias `claude`). Verify the command succeeds and reports prerequisites met. Verify `~/.claude/settings.json` is NOT modified (install is a check-only operation — no disk writes).

### 9.2 Claude Code integration — `integrations start claude` launches mount-namespace session
Run `sevorix integrations start claude`. Verify it execs `sevorix-claude-launcher`, which creates a mount namespace and bind-mounts sevsh over `/bin/bash`. Verify Claude Code launched within the session routes shell commands through sevsh (blocking policy-violating commands).

### 9.3 Claude Code integration — name aliases accepted
Run commands with both `claude` and `claude-code` as the integration name (e.g., `sevorix integrations status claude` and `sevorix integrations status claude-code`). Verify both are resolved to the same integration.

### 9.4 Claude Code integration — uninstall (prerequisite check only)
Run `sevorix integrations uninstall claude-code`. Verify no backup restoration occurs and `~/.claude/settings.json` is unaffected.

### 9.5 Claude Code integration — status
`sevorix integrations status claude-code`: Installed when prerequisites met (daemon running + sevsh present), NotInstalled otherwise.

### 9.6 Integration install pre-flight — daemon not running
Stop daemon. Run `sevorix integrations install claude-code`. Verify it fails with a clear error about the daemon not running.

### 9.7 Integration install pre-flight — sevsh not found
Remove or rename `~/.local/bin/sevsh`. Run `sevorix integrations install claude-code`. Verify clear error about sevsh not found.

### 9.8 Integrations list
`sevorix integrations list`. Verify all three integrations shown (claude-code, codex, openclaw).

### 9.9 Codex integration install/uninstall
Run install/uninstall for codex. Verify `~/.codex/config.json` is modified on install and restored on uninstall (codex uses the config-file approach).

### 9.10 OpenClaw integration with JSON5
Create `~/.openclaw/openclaw.json` with JSON5 comments. Run install. Verify comments are stripped gracefully and the `env.SHELL` or provider shell config is updated.

---

## 10. Hub Client

### 10.1 Register + Login + Status flow
`sevorix hub register -e test@example.com -p password`. Verify token saved.
`sevorix hub status`. Verify shows authenticated.
`sevorix hub logout`. Verify token removed.
`sevorix hub status`. Verify shows not authenticated.

### 10.2 Push artifact
Log in. Create a policy file. `sevorix hub push -n test-policy -v 1.0.0 -f policy.json`. Verify success response.

### 10.3 Pull artifact
`sevorix hub pull test-policy 1.0.0 -o ./pulled.json`. Verify file downloaded and content matches.

### 10.4 Pull with executable policy warning
Push a policy containing `type: Executable`. Pull it. Verify a security warning is displayed about executable policies.

### 10.5 Search
`sevorix hub search -q "test"`. Verify results include pushed artifact.

### 10.6 Yank / Unyank
`sevorix hub yank test-policy 1.0.0 -r "deprecated"`. Verify success.
`sevorix hub unyank test-policy 1.0.0`. Verify restored.

### 10.7 Push without auth
Log out. Attempt push. Verify authentication error.

---

## 11. sevsh — Secure Shell Wrapper

### 11.1 Fail-closed when daemon not running
Stop daemon. Run `sevsh`. Verify it refuses to start with a clear error about Watchtower being unreachable.

### 11.2 Interactive shell session
Start daemon. Run `sevsh`. Execute `echo hello`. Verify output. Exit shell. Verify session unregistered.

### 11.3 Command execution mode
`sevsh -- ls -la`. Verify output matches direct `ls -la` and a session was registered/unregistered.

### 11.4 Blocked command in shell
Start daemon with a policy blocking `rm -rf /`. Run `sevsh`. Type `rm -rf /`. Verify the command is blocked before execution.

### 11.5 Session registration
Start daemon. Run `sevsh`. GET `/api/active-sessions`. Verify the sevsh session ID appears. Exit shell. Verify session removed.

---

## 12. Traffic Logging

### 12.1 JSONL file created per session
Start/stop daemon twice. Verify two separate JSONL files in `~/.sevorix/logs/` with session UUIDs in filenames.

### 12.2 Log entry format includes role field
Trigger an event. Read the JSONL log. Verify fields: verdict, lane, layer, payload, timestamp (ISO 8601), latency, reason, confidence, context, role.

### 12.3 Log survives daemon restart
Generate events. Stop daemon. Verify log file persists and is readable.

---

## 13. Edge Cases & Error Handling

### 13.1 No policies loaded — GREEN if role configured, BLOCK if no role
Start daemon with empty `~/.sevorix/policies/` directory and a valid `default_role`. Send a request. Verify it defaults to ALLOW (GREEN — no policies match). Then start with no role configured. Verify BLOCK (fail-closed role enforcement fires before policy scan).

### 13.2 Malformed policy file — skipped gracefully
Place a malformed JSON file in `~/.sevorix/policies/`. Start daemon. Verify it starts successfully, logs a warning, and other policies still load.

### 13.3 Policy directory missing — falls back to legacy
Remove `~/.sevorix/policies/`. Place policies at `~/.config/sevorix/policies.json`. Start daemon. Verify legacy policies are loaded.

### 13.4 Proxy target unreachable
Proxy a request to a non-existent host. Verify the proxy returns an appropriate error (not a crash or hang).

### 13.5 Binary payload
Proxy a request with binary (non-UTF8) body content. Verify no panic; handled gracefully.

### 13.6 Very long URL
Proxy a request with an extremely long URL (>8000 chars). Verify no crash.

### 13.7 Stale PID file
Create a PID file pointing to a non-existent process. Run `sevorix start`. Verify it detects the stale PID, cleans up, and starts successfully.

---

## 14. Latency & Performance Contracts

### 14.1 GREEN lane latency < 50ms
Send 100 benign requests. Verify average overhead added by Watchtower is under 50ms.

### 14.2 RED lane latency < 10ms
Send 100 blocked requests. Verify average response time under 10ms (immediate block, no hold).

### 14.3 YELLOW lane holds connection until decision or timeout
Send a flagged request via proxy. Verify the response does not arrive until: (a) operator decides, or (b) `timeout_secs` elapses. Verify the hold duration matches configured timeout (within a reasonable margin).

### 14.4 Dashboard countdown accuracy
Configure `timeout_secs: 30`. Proxy a flagged request. Watch the dashboard countdown. Verify it starts at 30s and decrements in real time, pausing when Pause is clicked.

---

## 15. Multi-Layer Event Classification

### 15.1 Network layer events
Proxy a request. Verify the event's `layer` field is `"network"`.

### 15.2 Shell layer events
POST to `/analyze` with `context: "Shell"`. Verify the event's `layer` field is `"shell"`.

### 15.3 Layer filtering in event history
Generate events of different layers. GET `/api/events?layer=network`. Verify only network events returned. Repeat for shell.
