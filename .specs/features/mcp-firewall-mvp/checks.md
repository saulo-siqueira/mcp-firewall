# mcp-firewall-mvp checks

Profile: ui
Plan: `.specs/features/mcp-firewall-mvp/plan.md`

O repositório ainda não contém package manifest, task runner, CI ou testes. Por isso, cada proof abaixo nomeia um selector determinístico de teste, sem inventar um comando de execução; o runner concreto e o caminho dos testes serão definidos quando a implementação escolher a stack. Não há `Test policy`: não existe convenção de testes no repositório para responder ao nível de prova.

## Checks

### S1 - Gateway protege uma chamada MCP · proof selectors nomeados · escopo de arquivos a definir no build

**C1** - O gateway identifica `agent`, `server`, `tool` e `arguments` de uma chamada recebida (GATE-01, AC 1)
Proof: `test::gateway_identifies_tool_call_context`

**C2** - Uma política `enabled` com ação `allow` encaminha a chamada ao MCP Server alvo e devolve o resultado MCP (GATE-01, AC 2)
Proof: `test::gateway_forwards_call_with_explicit_allow`

**C3** - Uma política aplicável com ação `deny` devolve erro MCP de bloqueio e não chama o MCP Server alvo (GATE-01, AC 3)
Proof: `test::gateway_denies_call_without_target_invocation`

**C4** - Nenhuma política aplicável produz decisão `DENY` e não chama o MCP Server alvo (GATE-01, AC 4)
Proof: `test::gateway_defaults_to_deny_without_matching_policy`

**C5** - A precedência de políticas é `DENY` > `REQUIRE_APPROVAL` > `ALLOW` (GATE-01, AC 5)
Proof: `test::policy_precedence_restrictiveness_table`

**C6** - Um MCP Server configurado com transporte `stdio` é acessado por comunicação STDIO (GATE-01, AC 6)
Proof: `test::gateway_uses_stdio_transport`

**C7** - Um MCP Server configurado com transporte `http` é acessado por Streamable HTTP (GATE-01, AC 7)
Proof: `test::gateway_uses_streamable_http_transport`

### S2 - Redaction e auditoria · proof selectors nomeados · escopo de arquivos a definir no build

**C8** - API keys, tokens, passwords, private keys e environment secrets detectados são substituídos por `[REDACTED]` antes do encaminhamento (SEC-01, AC 8)
Proof: `test::secret_scanner_redacts_initial_categories_before_forwarding`

**C9** - Cada chamada `ALLOW`, `DENY` ou `REQUIRE_APPROVAL` produz um evento com `id`, `agent`, `server`, `tool`, `arguments`, `decision`, `policy`, `duration`, `result` e `created_at` (SEC-01, AC 9)
Proof: `test::audit_event_contains_required_fields_for_each_decision`

**C10** - O evento de uma chamada com segredo contém `[REDACTED]` e não contém o valor secreto bruto (SEC-01, AC 10)
Proof: `test::audit_event_never_persists_raw_secret`

### S3 - Aprovação humana · proof selectors nomeados · escopo de arquivos a definir no build

**C11** - Uma chamada `REQUIRE_APPROVAL` com mecanismo disponível cria uma solicitação `PENDING` com agente, ferramenta, servidor, argumentos redigidos, data e política (APR-01, AC 11)
Proof: `test::approval_request_starts_pending_with_redacted_context`

**C12** - Aprovar uma solicitação `PENDING` muda o estado para `APPROVED`, executa a chamada uma vez e registra `approved_by` e `approved_at` (APR-01, AC 12)
Proof: `test::approval_approve_executes_once_and_records_approver`

**C13** - Rejeitar uma solicitação `PENDING` muda o estado para `REJECTED` e não chama o MCP Server alvo (APR-01, AC 13)
Proof: `test::approval_reject_never_invokes_target`

**C14** - `REQUIRE_APPROVAL` sem mecanismo disponível não chama o MCP Server alvo e registra a decisão no audit log (APR-01, AC 14)
Proof: `test::approval_unavailable_blocks_and_audits`

### S4 - Administração autenticada · proof selectors nomeados · escopo de arquivos a definir no build

**C15** - Em instalação sem usuário, o setup cria o primeiro usuário com nome, email, senha confirmada e role `ADMIN` (ADM-01, AC 15)
Proof: `test::auth_setup_creates_first_admin`

**C16** - Após o setup, login cria sessão e direciona a sessão autenticada ao dashboard (ADM-01, AC 16)
Proof: `test::auth_login_creates_session_and_opens_dashboard`

**C17** - Credenciais inválidas não autenticam e não criam sessão autenticada (ADM-01, AC 17)
Proof: `test::auth_invalid_credentials_create_no_session`

**C18** - Sessão expirada ou invalidada por logout não acessa rota privada (ADM-01, AC 18)
Proof: `test::auth_expired_or_logged_out_session_is_rejected`

**C19** - Operações de listar, criar, editar, ativar, desativar e excluir política persistem a mudança e expõem a representação YAML (ADM-01, AC 19)
Proof: `test::policies_admin_crud_toggle_and_yaml_representation`

**C20** - Cadastro de MCP Server persiste `name`, `transport`, `command/url` e status inicial e aceita somente `stdio` ou `http` (ADM-01, AC 20)
Proof: `test::mcp_servers_accept_only_mvp_transports`

**C21** - Dashboard exibe Total Tool Calls, Allowed, Blocked, Requires Approval, série temporal, ferramentas mais usadas, chamadas recentes, políticas ativas e segredos interceptados (ADM-01, AC 21)
Proof: `test::dashboard_renders_required_metrics_and_sections`

**C22** - Tool Calls e Audit Logs exibem argumentos redigidos, política, resultado, duração e dados de aprovação no detalhe da chamada (ADM-01, AC 22)
Proof: `test::audit_detail_renders_redacted_call_and_approval_data`

**C23** - Approvals lista solicitações `PENDING` com contexto redigido e oferece Approve e Reject (ADM-01, AC 23)
Proof: `test::approvals_screen_lists_pending_requests_and_actions`

**C24** - MCP Servers exibe somente os statuses `Connected`, `Disconnected` ou `Error` no estado de cada servidor (ADM-01, AC 24)
Proof: `test::mcp_servers_screen_renders_allowed_statuses`

**C29** - Login/onboarding, Tool Calls, Policies e Settings possuem superfícies administrativas dedicadas dentro do Command Center (ADM-01, UI design)
Proof: `test::admin_screens_render_command_center_sections`

**C30** - Dashboard, Tool Calls, Policies, MCP Servers e Approvals expõem estados `Loading` e `Error` selecionáveis sem alterar a composição principal (ADM-01, UI design)
Proof: `test::admin_screens_expose_loading_and_error_states`

**C31** - A navegação do Command Center carrega as sete views administrativas por rota de view dedicada (ADM-01, UI design)
Proof: `test::admin_navigation_renders_each_route_view`

**C32** - Tool Calls, Policies e coleções de auditoria exibem dados persistidos do firewall e a API local retorna essas coleções em JSON (ADM-01, UI design)
Proof: `test::admin_screens_render_live_collections`

**C33** - A API administrativa cria a conta inicial, autentica a sessão e exige essa sessão para mutar políticas e MCP Servers (ADM-01, API boundary)
Proof: `test::admin_api_authenticates_and_mutates_resources`

**C34** - O formato YAML v1 é carregável pelo runtime e preserva match, ação, transporte e configuração inicial do servidor (CLI-01, configuration boundary)
Proof: `test::config_yaml_loads_policy_and_server_contract`

### S5 - Operação por CLI e headless · proof selectors nomeados · escopo de arquivos a definir no build

**C25** - `mcp-firewall init` cria `mcp-firewall.yaml` quando o arquivo não existe (CLI-01, AC 25)
Proof: `test::cli_init_creates_default_yaml`

**C26** - `mcp-firewall start` informa `Policies loaded`, `MCP servers`, `Gateway running` e `http://localhost:3210` (CLI-01, AC 26)
Proof: `test::cli_start_prints_mvp_startup_output`

**C27** - `mcp-firewall start --headless` inicia proxy MCP, policy engine e logs sem exigir dashboard (CLI-01, AC 27)
Proof: `test::cli_headless_starts_without_dashboard`

**C28** - `mcp-firewall init` com `mcp-firewall.yaml` existente não sobrescreve o arquivo e termina com exit code `1` (CLI-01, AC 28)
Proof: `test::cli_init_refuses_existing_yaml`

## Coverage

| Set (size) | Member -> proof | Unproven |
| --- | --- | --- |
| policy decisions (3) | `ALLOW` -> C2 · `DENY` -> C3 · `REQUIRE_APPROVAL` -> C11 | - |
| policy precedence outcomes (3) | `DENY` over `REQUIRE_APPROVAL` -> C5 · `REQUIRE_APPROVAL` over `ALLOW` -> C5 · `ALLOW` when no restrictive match -> C5 | - |
| MCP transports (2) | `stdio` -> C6 · `http` -> C7 | - |
| secret categories (5) | API keys -> C8 · tokens -> C8 · passwords -> C8 · private keys -> C8 · environment secrets -> C8 | - |
| approval states (3) | `PENDING` -> C11 · `APPROVED` -> C12 · `REJECTED` -> C13 | - |
| approval transitions (2) | `PENDING -> APPROVED` -> C12 · `PENDING -> REJECTED` -> C13 | - |
| audit decisions (3) | `ALLOW` -> C9 · `DENY` -> C9 · `REQUIRE_APPROVAL` -> C9 | - |
| users and sessions (2) | first `ADMIN` -> C15 · authenticated session -> C16 | - |
| MCP Server statuses (3) | `Connected` -> C24 · `Disconnected` -> C24 · `Error` -> C24 | - |
| CLI commands/modes (3) | `init` -> C25 · `start` -> C26 · `start --headless` -> C27 | - |
| Command Center admin screens (4) | Login/onboarding -> C29 · Tool Calls -> C29 · Policies -> C29 · Settings -> C29 | - |
| Command Center async states (2) | `Loading` -> C30 · `Error` -> C30 | - |
| Command Center navigation views (7) | `dashboard` -> C31 · `tool-calls` -> C31 · `policies` -> C31 · `mcp-servers` -> C31 · `approvals` -> C31 · `audit-logs` -> C31 · `settings` -> C31 | - |
| Live administrative collections (4) | Tool Calls -> C32 · Policies -> C32 · MCP Servers -> C32 · Audit Logs -> C32 | - |
| Authenticated administrative mutations (5) | setup/login -> C33 · policy create/update/delete -> C33 · server create -> C33 · approval reject -> C33 · logout rejection -> C33 | - |
| YAML configuration members (4) | policy match -> C34 · policy action -> C34 · server transport -> C34 · server command -> C34 | - |
| `tools/call` surface statuses (4) | `200` forwarded -> C2 · `403` denied -> C3 · `409` approval unavailable -> C14 · `502` transport failure -> C6 | - |
| `POST /api/auth/setup` statuses (3) | `201` -> C15 · `400` -> C15 · `409`/`422` -> C15 | - |
| `POST /api/auth/login` statuses (2) | `200` -> C16 · `401`/`422` -> C17 | - |
| `POST /api/auth/logout` statuses (2) | `204` -> C18 · `401` -> C18 | - |
| `GET /api/dashboard` statuses (2) | `200` -> C21 · `401`/`500` -> C18 | - |
| `/api/policies` statuses (8) | `200` -> C19 · `201` -> C19 · `204` -> C19 · `401` -> C18 · `403` -> C18 · `404` -> C19 · `409` -> C19 · `422` -> C19 | - |
| `/api/mcp-servers` statuses (4) | `200` -> C20 · `201` -> C20 · `401`/`403` -> C18 · `422` -> C20 | - |
| `/api/tool-calls` and `/api/audit-logs` statuses (3) | `200` -> C22 · `401` -> C18 · `404`/`422` -> C22 | - |
| `/api/approvals/:id/approve` statuses (5) | `200` -> C12 · `401` -> C18 · `403` -> C18 · `404` -> C12 · `409` -> C12 | - |
| `/api/approvals/:id/reject` statuses (5) | `200` -> C13 · `401` -> C18 · `403` -> C18 · `404` -> C13 · `409` -> C13 | - |
| `mcp-firewall init` exit/status values (2) | exit `0` -> C25 · exit `1`/`500` diagnostic -> C28 | - |
| `mcp-firewall start [--headless]` exit/status values (2) | exit `0` -> C26 · exit `1`/`500` diagnostic -> C26 | - |
| Relations entities (7) | `User` -> C15 · `Session` -> C18 · `Policy` -> C19 · `MCPServer` -> C20 · `ToolCall` -> C9 · `ApprovalRequest` -> C11 · `AuditEvent` -> C9 | - |
| Landing doors (10) | decision enum -> C5 · transport enum -> C6 · YAML v1 -> C19 · approval states -> C12 · `[REDACTED]` -> C8 · audit event -> C9 · session -> C18 · `/api` contract -> C19 · CLI commands -> C25 · one audit per call -> C9 | - |

- Claims about a route or status are proven at the boundary selectors above; no route is left without a Coverage row.
- The repository has no startup assemblies yet; startup configuration coverage is `n/a - no application entry point exists before BUILD`, so no assembly member is silently omitted.
- The plan's `Impact` has no existing callers or stored rows to re-read; this is covered by the repository inspection and will be revisited if BUILD introduces pre-existing data.

## Test policy

| Code | Required proofs | Coverage expectation |
| --- | --- | --- |
| Decision logic | one named behavior test per decision table or state transition | each member named in Coverage has an assertion at the decision layer |
| Boundary/UI/CLI behavior | one named test at each exposed boundary | each route, command, status and rendered UI obligation has a concrete assertion |
| Pass-through instrumentation | consumer proof only | no duplicate test required for a single forwarding call |

Evidence: this repository has no earlier test conventions; `test/mvp.test.js` is the first executable test surface. Cost: the 34 named proofs in this feature. Both rows are met by the current proof set; the UI review below additionally checks the binding source.

## Swept

- validation: C15, C19, C20, C25, C28
- failure modes: C3, C10, C14, C17, C26, C27, C28
- idempotency: C12, C13, C18, C28
- authorization: C18, C23
- concurrency: C12, C13
- data lifecycle: n/a - o MVP começa sem dados existentes e o PRD não define TTL, archival ou deletion lifecycle
- dependency failure: C6, C7, C14, C26, C27
- state transitions: C5, C11, C12, C13
- observability: C9, C21, C22
