# PRD — MCP Firewall

## 1. Visão Geral

### 1.1 Nome do produto
**MCP Firewall**

### 1.2 Resumo
O MCP Firewall é uma camada de segurança e governança posicionada entre agentes de IA e servidores MCP.

Seu objetivo é interceptar chamadas de ferramentas realizadas por agentes como Claude Code, Codex, Cursor e outros clientes compatíveis com MCP, avaliar essas chamadas através de políticas configuráveis e decidir se a execução deve ser permitida, bloqueada, sanitizada ou submetida à aprovação humana.

O produto deve fornecer:

- proteção contra operações destrutivas;
- controle sobre ferramentas acessíveis pelos agentes;
- proteção contra exposição de segredos;
- aprovação humana para ações sensíveis;
- histórico completo das execuções;
- auditoria de decisões;
- interface web para gerenciamento e monitoramento.

---

# 2. Problema

Agentes de IA com acesso a ferramentas externas podem realizar ações potencialmente perigosas.

Exemplos:

- excluir arquivos;
- alterar arquivos sensíveis;
- executar comandos no sistema operacional;
- consultar bases de produção;
- executar comandos destrutivos em bancos;
- criar ou fazer merge de pull requests;
- enviar informações sigilosas para ferramentas externas.

Hoje, o controle normalmente depende das permissões individuais de cada ferramenta ou MCP Server.

Isso cria um problema de governança.

Não existe uma camada central onde seja possível definir regras como:

```text
Claude pode consultar o banco de produção,
mas não pode executar comandos de escrita.
```

ou:

```text
Qualquer tentativa de merge de Pull Request
precisa de aprovação humana.
```

O MCP Firewall resolve esse problema através de uma camada intermediária de segurança.

---

# 3. Objetivo

Criar uma ferramenta open source capaz de atuar como gateway entre agentes de IA e MCP Servers.

O produto deve permitir:

1. interceptar chamadas MCP;
2. identificar agente, servidor e ferramenta;
3. avaliar políticas;
4. permitir, bloquear ou aguardar aprovação;
5. detectar e remover informações sensíveis;
6. registrar todas as operações;
7. fornecer uma interface administrativa.

---

# 4. Não objetivos do MVP

O MVP não deve tentar resolver:

- SaaS multi-tenant;
- organizações;
- times;
- billing;
- planos;
- SSO;
- OAuth;
- MFA;
- marketplace de políticas;
- Kubernetes;
- clusterização;
- alta disponibilidade;
- machine learning para decisões;
- classificação de risco baseada em IA;
- policy engines externos como OPA ou Cedar;
- gerenciamento empresarial avançado de identidade.

Esses itens poderão ser considerados após validação do projeto.

---

# 5. Público-alvo

Principalmente:

- desenvolvedores utilizando agentes de IA;
- equipes de engenharia;
- DevOps;
- Platform Engineering;
- times de segurança;
- desenvolvedores de MCP Servers.

Exemplos de agentes:

- Claude Code;
- Codex;
- Cursor;
- outros clientes compatíveis com MCP.

---

# 6. Proposta de valor

O usuário instala o MCP Firewall entre seu agente e seus MCP Servers.

Fluxo:

```text
AI Agent
   │
   │ MCP
   ▼
MCP Firewall
   │
   ├── Policy Engine
   ├── Secret Scanner
   ├── Approval Engine
   └── Audit Log
   │
   ▼
MCP Server
```

O agente continua utilizando MCP normalmente.

O firewall decide se cada chamada pode prosseguir.

---

# 7. Casos de uso principais

## UC01 — Permitir operação segura

Um agente solicita:

```text
filesystem.read
```

Existe uma política:

```yaml
tool: filesystem.read
action: allow
```

Resultado:

```text
ALLOW
```

A chamada deve ser encaminhada para o MCP Server.

---

## UC02 — Bloquear operação perigosa

O agente solicita:

```text
postgres.drop_table
```

Política:

```yaml
tool: postgres.drop_table
action: deny
```

Resultado:

```text
DENY
```

O MCP Server não deve receber a chamada.

---

## UC03 — Exigir aprovação

O agente solicita:

```text
github.merge_pull_request
```

Política:

```yaml
tool: github.merge_pull_request
action: require_approval
```

O Firewall deve:

1. suspender a execução;
2. criar uma solicitação de aprovação;
3. exibi-la no dashboard;
4. permitir que um usuário autenticado aprove ou rejeite;
5. executar a chamada somente após aprovação.

---

## UC04 — Proteger informações sensíveis

O agente envia:

```text
DATABASE_PASSWORD=my-secret-password
```

O Firewall identifica o valor sensível.

Antes de encaminhar:

```text
DATABASE_PASSWORD=[REDACTED]
```

O evento deve ser registrado no audit log.

---

## UC05 — Auditar operações

O administrador deve conseguir visualizar:

- agente;
- ferramenta;
- MCP Server;
- argumentos;
- decisão;
- política aplicada;
- duração;
- resultado;
- usuário responsável pela aprovação;
- data e hora.

---

# 8. Componentes

## 8.1 MCP Gateway

Responsável por receber chamadas MCP dos agentes.

Deve funcionar simultaneamente como:

```text
MCP Server
```

para o agente.

E:

```text
MCP Client
```

para os servidores MCP protegidos.

Fluxo:

```text
Agent
   ↓
MCP Server Interface
   ↓
Firewall
   ↓
MCP Client Interface
   ↓
Target MCP Server
```

---

# 9. Transportes MCP

O MVP deve suportar:

### STDIO

Para servidores MCP locais.

Exemplo:

```text
Claude Code
   ↓
MCP Firewall
   ↓
Filesystem MCP Server
```

### Streamable HTTP

Para servidores MCP remotos.

---

# 10. Policy Engine

O Policy Engine é o principal componente do sistema.

Ele recebe:

```text
ToolCall
```

e retorna:

```text
Decision
```

Decisões possíveis:

```text
ALLOW
DENY
REQUIRE_APPROVAL
```

Redaction deve ser tratada como transformação adicional e não necessariamente como decisão final.

---

# 11. Formato das políticas

As políticas devem poder ser definidas através de YAML.

Exemplo:

```yaml
version: 1

policies:

  - name: allow-read-files
    match:
      tool: filesystem.read
    action: allow

  - name: block-delete-files
    match:
      tool: filesystem.delete
    action: deny

  - name: require-approval-production
    match:
      server: production-db
      tool: postgres.*
    action: require_approval

  - name: block-drop-table
    match:
      tool: postgres.drop_table
    action: deny
```

---

# 12. Match de políticas

O MVP deve permitir match por:

```text
server
tool
agent
```

Exemplo:

```yaml
match:
  agent: claude-code
  server: production-db
  tool: postgres.query
```

Também deve existir suporte a wildcard:

```text
*
```

Exemplo:

```yaml
tool: postgres.*
```

---

# 13. Precedência de políticas

A ordem de prioridade deve ser:

```text
DENY
   ↓
REQUIRE_APPROVAL
   ↓
ALLOW
```

Ou seja:

Se múltiplas políticas forem aplicáveis, a política mais restritiva deve prevalecer.

Exemplo:

```text
ALLOW postgres.*

DENY postgres.drop_table
```

Resultado:

```text
postgres.query       → ALLOW
postgres.drop_table  → DENY
```

---

# 14. Comportamento sem política

O comportamento padrão do MVP será:

```text
DENY
```

Nenhuma chamada poderá ser executada se não existir uma política permitindo explicitamente sua execução.

Princípio:

```text
default deny
```

---

# 15. Secret Redaction

O Firewall deve conseguir identificar informações sensíveis nos argumentos enviados às ferramentas.

Categorias iniciais:

- API Keys;
- tokens;
- passwords;
- private keys;
- environment secrets.

Exemplos:

```text
API_KEY=abc123
```

deve se transformar em:

```text
API_KEY=[REDACTED]
```

---

# 16. Audit Log

Toda chamada deve gerar um evento de auditoria.

Mesmo chamadas bloqueadas.

Campos mínimos:

```text
id
agent
server
tool
arguments
decision
policy
duration
result
created_at
```

No caso de aprovação:

```text
approved_by
approved_at
```

---

# 17. Dashboard

O sistema deverá possuir uma interface web administrativa.

Principais áreas:

```text
Dashboard
Tool Calls
Policies
MCP Servers
Approvals
Audit Logs
Settings
```

---

# 18. Dashboard principal

A página inicial deve apresentar:

### Total Tool Calls

Quantidade total de chamadas.

### Allowed

Quantidade permitida.

### Blocked

Quantidade bloqueada.

### Requires Approval

Quantidade que exigiram aprovação.

Também deve apresentar:

- chamadas ao longo do tempo;
- ferramentas mais utilizadas;
- chamadas recentes;
- políticas ativas;
- segredos interceptados.

---

# 19. Tool Calls

Tela contendo tabela com:

```text
Time
Agent
Tool
MCP Server
Decision
Result
Duration
```

Ao selecionar uma chamada deve ser possível visualizar:

- argumentos;
- política aplicada;
- resultado;
- tempo de execução;
- dados de aprovação;
- eventos relacionados.

---

# 20. Policies

O usuário deve conseguir:

- listar políticas;
- criar política;
- editar política;
- ativar;
- desativar;
- excluir.

Campos:

```text
name
agent
server
tool
action
enabled
```

O sistema deve mostrar a representação YAML da política.

---

# 21. MCP Servers

O administrador deve conseguir cadastrar servidores MCP.

Campos iniciais:

```text
name
transport
command/url
status
```

Transportes:

```text
stdio
http
```

A tela deve mostrar:

```text
Connected
Disconnected
Error
```

---

# 22. Approval Flow

Chamadas classificadas como:

```text
REQUIRE_APPROVAL
```

devem ser exibidas em:

```text
Approvals
```

Informações:

```text
Agent
Tool
Server
Arguments
Requested At
Policy
```

Ações:

```text
Approve
Reject
```

Ao aprovar:

```text
PENDING
   ↓
APPROVED
   ↓
EXECUTE
```

Ao rejeitar:

```text
PENDING
   ↓
REJECTED
```

O MCP Server não deve receber a chamada rejeitada.

---

# 23. Autenticação

O dashboard deve possuir autenticação.

Fluxo:

```text
Login
  ↓
Dashboard
```

O MVP deve suportar:

- criação do primeiro usuário;
- login;
- logout;
- sessão persistente;
- proteção das rotas privadas.

---

# 24. Usuários

Modelo:

```text
users
```

Campos:

```text
id
name
email
password_hash
role
created_at
updated_at
```

Role inicial:

```text
ADMIN
```

Não haverá RBAC avançado no MVP.

---

# 25. Primeiro acesso

Caso não exista nenhum usuário cadastrado:

```text
Create Admin Account
```

O usuário informa:

```text
Name
Email
Password
Confirm Password
```

Após criação:

```text
Admin created
   ↓
Login
   ↓
Dashboard
```

---

# 26. Segurança da autenticação

As senhas nunca devem ser armazenadas em texto puro.

Devem utilizar hash apropriado para senhas.

Sessões devem:

- expirar;
- ser armazenadas de forma segura;
- permitir logout;
- invalidar sessões expiradas.

---

# 27. CLI

O produto deve possuir CLI.

Instalação esperada:

```bash
npm install -g mcp-firewall
```

Inicialização:

```bash
mcp-firewall init
```

Deve criar:

```text
mcp-firewall.yaml
```

Execução:

```bash
mcp-firewall start
```

Saída:

```text
MCP Firewall v0.1.0

Policies loaded: 7
MCP servers: 3

Gateway running.
Dashboard: http://localhost:3210
```

---

# 28. Funcionamento headless

O firewall deve poder funcionar sem o dashboard.

Exemplo:

```bash
mcp-firewall start --headless
```

Nesse modo:

- proxy MCP deve funcionar;
- policy engine deve funcionar;
- logs devem funcionar;
- dashboard não é necessário.

Funcionalidades que dependam de aprovação humana não poderão ser usadas sem um mecanismo de aprovação disponível.

---

# 29. Arquitetura

Estrutura sugerida:

```text
mcp-firewall/

apps/
  gateway/
  api/
  dashboard/

packages/
  mcp-proxy/
  policy-engine/
  security/
  database/
  shared/
  cli/

examples/
  filesystem/
  postgres/
  mock-mcp-server/

docs/
  architecture/
  adr/

docker-compose.yml
pnpm-workspace.yaml
README.md
```

---

# 30. Stack

## Backend

```text
Node.js 24 LTS
TypeScript
Fastify
Zod
MCP TypeScript SDK
```

## Frontend

```text
React
Vite
TypeScript
shadcn/ui
Tailwind CSS
TanStack Query
TanStack Table
React Router
```

## Persistência

```text
PostgreSQL
Drizzle ORM
```

## Testes

```text
Vitest
Testcontainers
Playwright
```

## Observabilidade

```text
Pino
OpenTelemetry
```

## Infraestrutura

```text
pnpm workspaces
Docker
Docker Compose
GitHub Actions
```

---

# 31. Modelo de dados inicial

## users

```text
id
name
email
password_hash
role
created_at
updated_at
```

## sessions

```text
id
user_id
expires_at
created_at
```

## mcp_servers

```text
id
name
transport
config
status
created_at
updated_at
```

## policies

```text
id
name
agent
server
tool
action
enabled
created_at
updated_at
```

## tool_calls

```text
id
agent
server_id
tool_name
arguments
decision
result
duration_ms
policy_id
created_at
```

## approvals

```text
id
tool_call_id
status
requested_at
resolved_at
resolved_by
```

## audit_logs

```text
id
event
actor
metadata
created_at
```

---

# 32. Observabilidade

O gateway deve gerar traces para o processamento de uma chamada.

Exemplo:

```text
mcp.tool_call
   │
   ├── policy.match
   ├── policy.evaluate
   ├── secret.scan
   ├── approval.check
   └── mcp.forward
```

Métricas desejadas:

```text
tool_calls_total
tool_calls_allowed
tool_calls_denied
tool_calls_pending_approval
tool_call_duration
secrets_redacted
```

---

# 33. Logs

Logs estruturados devem ser utilizados.

Exemplo:

```json
{
  "event": "tool_call",
  "agent": "claude-code",
  "tool": "postgres.drop_table",
  "decision": "deny",
  "policy": "block-destructive-db"
}
```

Informações sensíveis nunca devem aparecer nos logs.

---

# 34. Testes

## Unitários

Cobertura obrigatória do Policy Engine.

Cenários:

```text
exact tool match
wildcard match
server match
agent match
deny overrides allow
approval overrides allow
default deny
disabled policies ignored
```

---

# 35. Testes de integração

Deve existir um Mock MCP Server.

Arquitetura:

```text
Test MCP Client
      ↓
MCP Firewall
      ↓
Mock MCP Server
```

Cenários obrigatórios:

### Allow

```text
tool call
→ firewall
→ allow
→ MCP server receives request
```

### Deny

```text
tool call
→ firewall
→ deny

MCP server must NOT receive request
```

### Approval

```text
tool call
→ firewall
→ pending approval
→ approve
→ MCP server receives request
```

---

# 36. E2E

Playwright deve validar:

```text
Login
Dashboard
Create policy
Edit policy
Disable policy
Approve request
Reject request
View audit event
```

---

# 37. Docker

O projeto deve executar localmente utilizando:

```bash
docker compose up
```

Serviços mínimos:

```text
PostgreSQL
MCP Firewall
Dashboard/API
```

---

# 38. Developer Experience

O projeto deve permitir:

```bash
git clone
pnpm install
pnpm dev
```

E para infraestrutura:

```bash
docker compose up -d postgres
```

---

# 39. README

O README deverá apresentar imediatamente o problema resolvido.

Exemplo:

```text
Claude Code
     ↓

postgres.drop_table("users")

     ↓

MCP Firewall

     ↓

BLOCKED

Policy: block-destructive-database-actions
```

Seções:

```text
What is MCP Firewall?
Why?
Architecture
Quick Start
Configuration
Policies
Dashboard
CLI
Security
Development
Roadmap
Contributing
```

---

# 40. Critérios de aceite do MVP

O MVP será considerado concluído quando for possível:

1. iniciar o projeto localmente com Docker;
2. criar o primeiro usuário administrador;
3. realizar login;
4. cadastrar um MCP Server;
5. configurar um agente para passar pelo firewall;
6. executar uma ferramenta permitida;
7. visualizar a chamada no dashboard;
8. bloquear uma ferramenta através de política;
9. comprovar que o servidor MCP não recebeu a chamada bloqueada;
10. solicitar aprovação para uma ferramenta;
11. aprovar a chamada pelo dashboard;
12. executar a chamada após aprovação;
13. rejeitar uma chamada;
14. aplicar wildcard em políticas;
15. utilizar comportamento `default deny`;
16. identificar e remover um secret;
17. consultar todo o histórico no audit log;
18. executar testes unitários e de integração;
19. executar o firewall pela CLI;
20. executar o core sem depender da interface web.

---

# 41. Métricas de sucesso

Para o MVP técnico:

```text
100% das chamadas devem passar pelo Policy Engine.

0 chamadas DENY devem alcançar o MCP Server.

100% das chamadas devem gerar audit log.

100% das aprovações devem possuir identificação do usuário.

Nenhum secret identificado deve aparecer nos logs.
```

Indicadores open source futuros:

```text
GitHub stars
Forks
Contributors
Downloads NPM
Issues abertas pela comunidade
MCP Servers testados
```

---

# 42. Roadmap

## v0.1 — Firewall

```text
MCP proxy
Policy Engine
ALLOW
DENY
REQUIRE_APPROVAL
Default deny
STDIO
Streamable HTTP
Audit log
```

## v0.2 — Dashboard

```text
Authentication
Users
Dashboard
Tool calls
Policies
Approvals
MCP Servers
```

## v0.3 — Security

```text
Secret detection
Redaction
Sensitive file policies
Command restrictions
```

## v0.4 — Observability

```text
OpenTelemetry
Metrics
Tracing
Performance dashboard
```

## v0.5 — Developer Experience

```text
CLI improvements
Policy templates
Better setup
Examples
Additional MCP integrations
```

## Futuro

```text
RBAC
Teams
Organizations
SSO
Policy packs
Risk scoring
Cloud deployment
Webhook approvals
Slack approvals
GitHub approvals
Policy simulation
Policy testing
Policy-as-code CI
```

---

# 43. Princípios técnicos

O projeto deve seguir estes princípios:

### Secure by default

```text
default deny
```

### Core independente

O firewall não pode depender do dashboard.

### Policy as Code

Todas as políticas devem ser representáveis em configuração.

### Audit everything

Toda decisão deve gerar evidência auditável.

### No hidden AI decisions

O MVP não deve utilizar LLM para decidir se uma operação é permitida.

As decisões precisam ser:

```text
determinísticas
explicáveis
reproduzíveis
```

### Simplicidade

Não adicionar abstrações antes de existir necessidade real.

### Open source first

A experiência principal deve funcionar localmente sem serviços proprietários.

---

# 44. Definição final do MVP

O MVP deve demonstrar claramente este cenário:

```text
Claude Code
     │
     │ postgres.drop_table
     ▼
MCP Firewall
     │
     │ Policy Engine
     ▼

BLOCKED

Reason:
Policy "block-destructive-database-actions"

Action:
DENY

Audit event created.
```

E este:

```text
Claude Code
     │
     │ github.merge_pull_request
     ▼
MCP Firewall
     │
     ▼
WAITING FOR APPROVAL

Dashboard
     │
     ▼

Administrator clicks APPROVE

     │
     ▼

MCP Firewall
     │
     ▼

GitHub MCP Server

     │
     ▼

SUCCESS
```

Esses dois fluxos serão a principal demonstração funcional do projeto.