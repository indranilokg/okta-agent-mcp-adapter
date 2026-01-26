# Okta Agent Proxy

A production-ready proxy for MCP (Model Context Protocol) clients with OAuth 2.1 authentication, multi-agent support, and cross-app token exchange.

## Overview

**Status**: ✅ Complete (113 tests passing)

The Okta Agent Proxy provides:
- ✅ Multi-backend MCP proxying with path-based routing
- ✅ Okta OAuth 2.1 JWT validation with JWKS caching
- ✅ RFC-compliant ID-JAG token exchange for backend access
- ✅ Multi-agent support (per-client authorization and credentials)
- ✅ 3 authentication methods: Okta Cross-App, Pre-Shared Key, Service Account
- ✅ Token caching with TTL and automatic expiration handling
- ✅ Comprehensive audit logging and SQLite persistence
- ✅ Protected Resource Metadata discovery (RFC9728)

## Quick Start

```bash
# Setup
cp env.template .env
# Edit .env with Okta credentials

# Install & test
pip install -r requirements.txt
pytest tests/  # 113 tests, all passing

# Start agent proxy
python -m okta_agent_proxy.main http
# or: ./scripts/run_gateway.sh
```

## Configuration

### .env (Environment Variables)
```bash
OKTA_DOMAIN=dev-12345.okta.com
OKTA_CLIENT_ID=0oa1234567890abcdef
OKTA_CLIENT_SECRET=xxxxxxxxxxxx
OKTA_ISSUER=https://dev-12345.okta.com
GATEWAY_BASE_URL=http://localhost:8000
GATEWAY_PORT=8000
LOG_LEVEL=INFO
```

### config/config.yaml (Backends & Agents)
```yaml
backends:
  employees:
    url: http://localhost:9001
    paths: [/employees, /hr]
    auth_method: okta-cross-app
    auth_config:
      id_jag_mode: static
      target_authorization_server: https://target-okta.okta.com
      target_token_endpoint: https://target-okta.okta.com/oauth2/v1/token
      target_client_id: 0oa_target_app
      target_client_secret: secret

  partners:
    url: http://localhost:9002
    paths: [/partners]
    auth_method: pre-shared-key
    auth_config:
      key: partner_api_key_123

agents:
  cursor:
    client_id: 0oa_cursor_app
    private_key: |
      -----BEGIN PRIVATE KEY-----
      MIIEvQIBADANBgkqhkiG9w0BAQEFAASCA...
      -----END PRIVATE KEY-----
    scopes: [mcp:read, mcp:write]
    backend_access: [employees, finance]

  claude-code:
    client_id: 0oa_claude_code
    private_key: ...
    scopes: [mcp:read]
    backend_access: [partners]
```

## Architecture

### Request Flow
```
MCP Client (X-Agent-ID: cursor + Bearer Token)
    ↓
Agent Proxy
├─ 1. Validate Okta JWT
├─ 2. Extract Agent ID
├─ 3. Load Agent Config (backend_access)
├─ 4. Route to Backend
├─ 5. Authorize (backend in agent.backend_access?)
├─ 6. Exchange Token (ID-JAG)
├─ 7. Add Auth Headers
└─ 8. Forward Request
    ↓
Target MCP Backend → Response
```

### Key Components
- **ProxyHandler** - Request processing pipeline
- **BackendRouter** - Path-based routing
- **OktaTokenValidator** - JWT validation
- **AgentExtractor** - Multi-agent support
- **InMemoryBackendStore** - SQLite + YAML persistence
- **ID-JAG Issuer/Exchanger** - Two-step token exchange
- **BackendAuthHandler** - 3 auth methods

### Token Exchange (ID-JAG)
```
Step 1: Client sends Okta token
Step 2: Gateway issues ID-JAG JWT (using agent credentials)
Step 3: Exchange ID-JAG JWT for backend token (at target auth server)
Step 4: Cache backend token with TTL
Step 5: Use cached token until expiration
Step 6: On 401: Invalidate cache, retry exchange
```

## Implementation Status

| Phase | Feature | Status | Tests |
|-------|---------|--------|-------|
| 1 | Basic Proxy | ✅ | 17 |
| 1B | SQLite Storage + YAML | ✅ | 20 |
| 2 | Okta JWT Validation | ✅ | 41 |
| 2+ | Multi-Agent Support | ✅ | 53 |
| 3 | Token Exchange & Proxying | ✅ | Integrated |
| **Total** | | **✅ Complete** | **113** |

## Project Structure

```
okta_agent_proxy/
├── main.py                    # FastMCP entry point
├── config.py                  # Configuration management
├── auth/
│   ├── okta_validator.py      # JWT validation
│   ├── agent_authz.py         # Multi-agent authorization
│   ├── backend_auth.py        # 3 auth methods
│   ├── id_jag_issuer.py       # ID-JAG JWT issuing
│   └── id_jag_exchanger.py    # Token exchange
├── middleware/
│   ├── auth.py                # Auth utilities
│   └── agent_extractor.py     # Agent extraction
├── backends/
│   └── router.py              # Path-based routing
├── proxy/
│   └── handler.py             # Request proxying
├── storage/
│   ├── base.py                # Abstract interface
│   ├── models.py              # SQLAlchemy ORM
│   └── in_memory.py           # SQLite implementation
└── cache/                     # Token caching

tests/
├── test_basic_gateway.py      # 17 tests
├── test_okta_auth.py          # 41 tests
├── test_in_memory_store.py    # 20 tests
├── test_agent_support.py      # 26 tests
└── test_agent_authz.py        # 27 tests
```

## Usage Examples

### Testing
```bash
# All tests (113 tests, 0.29s)
pytest tests/ -v

# Specific test file
pytest tests/test_agent_authz.py -v

# With coverage
pytest tests/ --cov=okta_agent_proxy
```

### Client Request (with Agent)
```bash
curl -H "Authorization: Bearer <okta_token>" \
     -H "X-Agent-ID: cursor" \
     -H "Accept: application/json, text/event-stream" \
     -d '{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}}' \
     http://localhost:8000/employees
```

### Response (Success)
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": { "tools": [...] }
}
```

### Response (Authorization Error)
```json
{
  "error": "authorization_denied",
  "message": "Not authorized to access backend 'finance'",
  "agent_id": "cursor"
}
```

## Multi-Agent Authorization

Each agent has:
- **client_id**: OAuth app ID (for ID-JAG)
- **private_key**: PKCS8 key (for token exchange)
- **scopes**: Required permissions (default: mcp:read)
- **backend_access**: List of backends the agent can access

Example flow:
```
Client (Cursor agent) 
  + X-Agent-ID: cursor
  + Authorization: Bearer <token>
  ↓
Gateway checks:
  ✓ Agent 'cursor' exists and enabled
  ✓ User has 'mcp:read' scope
  ✓ Backend 'employees' in agent.backend_access
  ✓ Exchange token for backend
  ↓
Allow → Forward to backend
```

## Troubleshooting

**Port already in use**: Change `GATEWAY_PORT=8001` in `.env`

**Import errors**: `pip install -r requirements.txt --force-reinstall`

**Okta token validation fails**: Verify `OKTA_DOMAIN`, `OKTA_CLIENT_ID`, `OKTA_ISSUER` in `.env`

**Agent not found**: Add agent to `config/config.yaml` and ensure `X-Agent-ID` header matches

**Backend authorization denied**: Check agent's `backend_access` list in config

**Enable debug logging**: `LOG_LEVEL=DEBUG python -m okta_agent_proxy.main http`

## Diagrams & Visual Documentation

Visual architecture and sequence diagrams are available in the `/docs/` folder:

- **ARCHITECTURE_DIAGRAM.md** - System architecture with Mermaid diagrams
  - Complete component visualization
  - 7-layer proxy architecture
  - Data flow through each layer
  - Security boundaries
  - Multi-agent configuration
  - Token exchange flows

- **SEQUENCE_DIAGRAM.md** - Request flow sequences
  - Complete flow: Claude Code agent → Employee MCP via proxy
  - 5 phases: Auth → Discovery → Request → TokenEx → Refresh
  - 6 error scenarios with handling
  - 4 use cases
  - Component interactions

**View Diagrams**:
- [Mermaid Live](https://mermaid.live/) - Copy architecture diagrams
- [sequencediagram.org](https://www.sequencediagram.org/) - Copy sequence diagrams
- GitHub - Auto-renders Mermaid diagrams
- VS Code + Mermaid extension

## References

- [MCP Specification](https://modelcontextprotocol.io/)
- [Okta Developer Docs](https://developer.okta.com/)
- [OAuth 2.1 Spec](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-09)
- [ID-JAG Draft](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-00.html)

## Status

✅ **Production Ready** - Ready for integration testing with real Okta tenants and MCP servers

License: Apache 2.0

