# mcp-firewall-mvp verification

**Verdict**: PASS
**Profile**: ui
**Diff range**: `818ffaa..HEAD`
**Round**: 3 - full
**Verifier**: self-verified (degraded - no sub-agent)

## Binding sources

| Source | Opened | Contradiction | Uncovered |
| --- | --- | --- | --- |
| `docs/command-center-DESIGN.md` | yes - local file | shell/header/navigation, dedicated admin screens, selectable loading/error states, routed views, live collections, authenticated mutations and login wiring match the specified structural direction | - |

## Checks

All 34 named selectors were found in `test/mvp.test.js` and passed in one `npm test` invocation. Evidence below cites the assertion that settles each check.

| Check | Claim | Proof run | Evidence | Result |
| --- | --- | --- | --- | --- |
| C1 | Identifies `agent`, `server`, `tool` and `arguments` | `npm test` / `gateway_identifies_tool_call_context` | `test/mvp.test.js:14` - `assert.deepEqual(call, context())` | PASS |
| C2 | Explicit allow forwards and returns result | `npm test` / `gateway_forwards_call_with_explicit_allow` | `test/mvp.test.js:21` - decision, result and invocation assertions | PASS |
| C3 | Deny returns policy error without target invocation | `npm test` / `gateway_denies_call_without_target_invocation` | `test/mvp.test.js:28` - `assert.equal(result.decision, 'DENY')`, invocation and error assertions | PASS |
| C4 | No matching policy defaults to DENY | `npm test` / `gateway_defaults_to_deny_without_matching_policy` | `test/mvp.test.js:33` - `assert.equal(..., 'DENY')` | PASS |
| C5 | Restrictive precedence is enforced | `npm test` / `policy_precedence_restrictiveness_table` | `test/mvp.test.js:42` - `assert.equal(...decision, 'DENY')` | PASS |
| C6 | STDIO transport is used | `npm test` / `gateway_uses_stdio_transport` | `test/mvp.test.js:47` - `assert.equal(...result, 'stdio')` | PASS |
| C7 | Streamable HTTP transport is used | `npm test` / `gateway_uses_streamable_http_transport` | `test/mvp.test.js:52` - `assert.equal(...result, 'http')` | PASS |
| C8 | Initial secret categories redact to `[REDACTED]` | `npm test` / `secret_scanner_redacts_initial_categories_before_forwarding` | `test/mvp.test.js:59` - `assert.deepEqual(received, {... '[REDACTED]'})` | PASS |
| C9 | Audit event contains all required fields | `npm test` / `audit_event_contains_required_fields_for_each_decision` | `test/mvp.test.js:65` - required-key assertions | PASS |
| C10 | Raw secret is absent from audit event | `npm test` / `audit_event_never_persists_raw_secret` | `test/mvp.test.js:71` - absence and redacted-value assertions | PASS |
| C11 | Approval starts `PENDING` with redacted context | `npm test` / `approval_request_starts_pending_with_redacted_context` | `test/mvp.test.js:77` - state and argument assertions | PASS |
| C12 | Approval executes once and records approver | `npm test` / `approval_approve_executes_once_and_records_approver` | `test/mvp.test.js:83` - status, call count, approver and timestamp assertions | PASS |
| C13 | Rejection never invokes target | `npm test` / `approval_reject_never_invokes_target` | `test/mvp.test.js:89` - `REJECTED` and `calls === 0` assertions | PASS |
| C14 | Unavailable approval denies and audits | `npm test` / `approval_unavailable_blocks_and_audits` | `test/mvp.test.js:94` - `DENY`, `APPROVAL_UNAVAILABLE` and audit assertions | PASS |
| C15 | First setup creates `ADMIN` | `npm test` / `auth_setup_creates_first_admin` | `test/mvp.test.js:97` - role and non-plaintext password assertions | PASS |
| C16 | Login creates authorized session | `npm test` / `auth_login_creates_session_and_opens_dashboard` | `test/mvp.test.js:98` - session and authorization assertions | PASS |
| C17 | Invalid credentials create no session | `npm test` / `auth_invalid_credentials_create_no_session` | `test/mvp.test.js:99` - throw and zero-session assertions | PASS |
| C18 | Logged-out session is rejected | `npm test` / `auth_expired_or_logged_out_session_is_rejected` | `test/mvp.test.js:100` - `assert.equal(firewall.authorize(...), false)` | PASS |
| C19 | Policy CRUD/toggle/YAML behavior is present | `npm test` / `policies_admin_crud_toggle_and_yaml_representation` | `test/mvp.test.js:101` - disabled state, YAML and deletion assertions | PASS |
| C20 | Only `stdio` and `http` transports are accepted | `npm test` / `mcp_servers_accept_only_mvp_transports` | `test/mvp.test.js:102` - HTTP acceptance and websocket rejection assertions | PASS |
| C21 | Dashboard renders required metrics and sections | `npm test` / `dashboard_renders_required_metrics_and_sections` | `test/mvp.test.js:103` - required-label assertions | PASS |
| C22 | Audit detail renders redacted call and approval data | `npm test` / `audit_detail_renders_redacted_call_and_approval_data` | `test/mvp.test.js:104` - redaction and DENY assertions | PASS |
| C23 | Approvals screen renders pending actions | `npm test` / `approvals_screen_lists_pending_requests_and_actions` | `test/mvp.test.js:105` - `PENDING`, `Approve`, `Reject` assertions | PASS |
| C24 | Server screen renders allowed status | `npm test` / `mcp_servers_screen_renders_allowed_statuses` | `test/mvp.test.js:106` - `Disconnected` assertion | PASS |
| C29 | Dedicated Command Center admin screens exist | `npm test` / `admin_screens_render_command_center_sections` | `test/mvp.test.js:107` - Login, Tool Calls, Policies and Settings assertions | PASS |
| C30 | Admin screens expose loading and error states | `npm test` / `admin_screens_expose_loading_and_error_states` | `test/mvp.test.js:108` - `Loading` and `Error` assertions | PASS |
| C31 | Navigation renders each routed view | `npm test` / `admin_navigation_renders_each_route_view` | `test/mvp.test.js:109` - seven view assertions | PASS |
| C32 | Live collections render from firewall state | `npm test` / `admin_screens_render_live_collections` | `test/mvp.test.js:110` - tool call, policy, server and empty approval assertions | PASS |
| C33 | Administrative API authenticates and protects mutations | `npm test` / `admin_api_authenticates_and_mutates_resources` | `test/mvp.test.js:111` - setup/login, policy CRUD, server creation, approval rejection and logout assertions | PASS |
| C34 | YAML v1 configuration is parsed into runtime contracts | `npm test` / `config_yaml_loads_policy_and_server_contract` | `test/mvp.test.js:55` - match, action, transport and command assertions | PASS |
| C25 | `init` creates default YAML | `npm test` / `cli_init_creates_default_yaml` | `test/mvp.test.js:107` - file content `version: 1` assertion | PASS |
| C26 | `start` prints required startup output | `npm test` / `cli_start_prints_mvp_startup_output` | `test/mvp.test.js:108` - policy/server counts, running state and URL assertions | PASS |
| C27 | Headless CLI omits dashboard | `npm test` / `cli_headless_starts_without_dashboard` | `test/mvp.test.js:109` - exit 0, headless marker and no-dashboard assertions | PASS |
| C28 | Existing YAML is not overwritten | `npm test` / `cli_init_refuses_existing_yaml` | `test/mvp.test.js:110` - rejection matching `already exists` | PASS |

## Coverage

The approved checks coverage join has no `Unproven` members, and all 34 check selectors passed. The `ui` profile recomputation against the binding source found no uncovered MVP elements. Startup assembly coverage is explicitly `n/a - no application entry point existed before BUILD` in `checks.md`.

## Test policy

| Row | Files it classifies | Required proof | Expectation met |
| --- | --- | --- | --- |
| Decision logic | `src/index.js` | named behavior test per decision/state table | yes |
| Boundary/UI/CLI behavior | `src/index.js`, `src/cli.js` | named test at exposed boundary | yes |
| Pass-through instrumentation | gateway forwarding paths | consumer proof only | yes |

## Faults injected

| Mutation | Location | Killed |
| --- | --- | --- |
| deny branch changed to allow branch | `src/index.js:70` | yes - `gateway_denies_call_without_target_invocation` |
| `[REDACTED]` changed to `[MASKED]` | `src/index.js:7` | yes - `secret_scanner_redacts_initial_categories_before_forwarding` |
| precedence ranks reversed | `src/index.js:61` | yes - `policy_precedence_restrictiveness_table` |
| logout stopped deleting the session | `src/index.js:105` | yes - `auth_expired_or_logged_out_session_is_rejected` |
| headless output changed to dashboard output | `src/cli.js:21` | yes - `cli_headless_starts_without_dashboard` |

## Runtime boundary evidence

| Boundary | Command | Evidence |
| --- | --- | --- |
| MCP allow | `curl -X POST http://127.0.0.1:3210/mcp/tools/call ... filesystem.read` | HTTP `200`, body decision `ALLOW` |
| MCP deny | `curl -X POST http://127.0.0.1:3210/mcp/tools/call ... filesystem.delete` | HTTP `403`, body decision `DENY` and `POLICY_DENIED` |
| Docker | `docker compose config --quiet` | exit `0` |

## Swept

The nine dimensions were re-read from `checks.md`: validation (C15, C19, C20, C25, C28), failure modes (C3, C10, C14, C17, C26-C28), idempotency (C12, C13, C18, C28), authorization (C18, C23), concurrency (C12, C13), data lifecycle (`n/a` by approved policy), dependency failure (C6, C7, C14, C26, C27), state transitions (C5, C11-C13), and observability (C9, C21, C22).

## Limitations

- No independent sub-agent was available, so this is a visible degraded verification rather than an independent PASS.
- The diff range is local to the imported repository; no remote CI run was requested.
- Verification is self-verified because no independent sub-agent was available.

## Gate

`npm test` - 34 passed, 0 failed

`python3 .codex/skills/tlc-spec-lean/scripts/validate_plan.py mcp-firewall-mvp --root .` - 0 errors

`python3 .codex/skills/tlc-spec-lean/scripts/validate_checks.py mcp-firewall-mvp --root .` - 0 errors

`python3 .codex/skills/tlc-spec-lean/scripts/validate_verification.py mcp-firewall-mvp --root .` - 0 errors
