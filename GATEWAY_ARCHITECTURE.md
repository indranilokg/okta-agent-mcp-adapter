# Okta Agent Proxy - Architecture

## System Overview

```mermaid
graph TB
    subgraph Clients["🔐 Clients (Agents)"]
        Cursor["Cursor/VSCode"]
        Claude["Claude"]
        Copilot["Copilot"]
    end

    subgraph Gateway["🌐 Okta Agent Proxy Gateway"]
        Main["main.py<br/>Entry Point"]
        
        subgraph Auth["🔑 Authentication Layer"]
            OAuthDisc["OAuth Discovery<br/>/.well-known/oauth-*"]
            DCR["Dynamic Client Registration<br/>/oauth2/register"]
            TokenEP["Token Endpoint<br/>/oauth2/v1/token"]
            Validator["OktaTokenValidator<br/>JWT validation"]
        end
        
        subgraph Routing["📍 Request Routing"]
            Middleware["Auth Middleware<br/>Extract token & agent"]
            ProxyHandler["ProxyHandler<br/>Route to backend"]
            SessionMgr["SessionManager<br/>Maintain MCP sessions"]
        end
        
        subgraph Exchange["🔄 Token Exchange"]
            CrossApp["OktaCrossAppAccessManager<br/>ID-JAG (RFC8693)"]
            BackendRouter["BackendRouter<br/>Backend token logic"]
            Cache["TokenCache<br/>Cache tokens"]
        end
        
        subgraph Discovery["🔍 Discovery"]
            MetadataClient["MetadataDiscoveryClient<br/>RFC9728 metadata"]
            AuthzClient["BackendToolsDiscovery<br/>Get available tools"]
        end
        
        subgraph Storage["💾 Configuration"]
            Store["InMemoryBackendStore<br/>SQLite backends/agents"]
            Config["config.yaml<br/>Loaded settings"]
        end
    end

    subgraph Backends["🛠️ Backend MCP Servers"]
        Employees["Employee MCP<br/>Port 8001"]
        Partners["Partner MCP<br/>etc"]
    end

    subgraph Okta["☁️ Okta Authorization"]
        AuthServer["Authorization Server<br/>ID-JAG target"]
        JWKS["JWKS Endpoint<br/>Verify tokens"]
    end

    %% Client flows
    Cursor -->|OAuth flow| OAuthDisc
    Claude -->|OAuth flow| OAuthDisc
    Copilot -->|OAuth flow| OAuthDisc
    
    OAuthDisc --> TokenEP
    DCR --> Config
    TokenEP --> Validator
    TokenEP -->|Send token| CrossApp
    
    %% Request flow
    Clients -->|tools/list| Middleware
    Middleware --> ProxyHandler
    ProxyHandler -->|Get agent config| Store
    ProxyHandler -->|Exchange token| BackendRouter
    
    BackendRouter -->|Fresh manager| CrossApp
    CrossApp -->|ID-JAG steps| AuthServer
    CrossApp -->|Cache hit?| Cache
    Cache -->|Verify JWT| JWKS
    
    ProxyHandler -->|Get/create session| SessionMgr
    SessionMgr -->|Forward MCP request| Employees
    
    ProxyHandler -->|Dynamic discovery| MetadataClient
    ProxyHandler -->|List tools| AuthzClient
    
    Config -->|Load on startup| Store
    Store -->|Query backends| BackendRouter
    
    Employees -->|MCP response| SessionMgr
    SessionMgr -->|JSON-RPC| Clients
    
    AuthServer -->|Issue tokens| Cache
    JWKS -->|Public keys| Validator
    
    style Gateway fill:#e1f5ff
    style Auth fill:#fff3e0
    style Routing fill:#f3e5f5
    style Exchange fill:#e8f5e9
    style Discovery fill:#fce4ec
    style Storage fill:#f1f8e9
    style Okta fill:#ffe0b2
    style Clients fill:#e0f2f1
    style Backends fill:#f5f5f5
```

---

## Component Details

### 🔑 Authentication Layer (`auth/`)

| Component | File | Purpose |
|-----------|------|---------|
| **OktaTokenValidator** | `okta_validator.py` | JWT validation, JWKS caching, audience checking |
| **OktaCrossAppAccessManager** | `cross_app_access.py` | ID-JAG token exchange (RFC8693) using Okta AI SDK |
| **OAuth Endpoints** | `main.py` | DCR, authorize, token endpoints |

### 📍 Request Routing (`proxy/` + `middleware/`)

| Component | File | Purpose |
|-----------|------|---------|
| **ProxyHandler** | `proxy/handler.py` | Main request router, auth validation, backend selection |
| **SessionManager** | `proxy/session_manager.py` | MCP session creation, caching, header management |
| **Auth Middleware** | `middleware/auth.py` | Extract bearer tokens, agent identity |
| **MCP Transparent Proxy** | `middleware/mcp_transparent_proxy.py` | Determine if request needs forwarding |

### 🔄 Token Exchange (`backends/` + `cache/`)

| Component | File | Purpose |
|-----------|------|---------|
| **BackendRouter** | `backends/router.py` | Coordinate token exchange, determine ID-JAG mode |
| **TokenCache** | `cache/token_cache.py` | In-memory token caching with TTL |
| **OktaCrossAppAccessManager** | `auth/cross_app_access.py` | 4-step ID-JAG flow |

### 🔍 Discovery (`discovery/`)

| Component | File | Purpose |
|-----------|------|---------|
| **MetadataDiscoveryClient** | `discovery/metadata_client.py` | RFC9728 metadata discovery for dynamic mode |
| **BackendToolsDiscovery** | `discovery/backend_tools.py` | Discover available MCP tools from backends |

### 💾 Configuration (`storage/` + `config.py`)

| Component | File | Purpose |
|-----------|------|---------|
| **InMemoryBackendStore** | `storage/in_memory.py` | SQLite in-memory DB, loads YAML on startup |
| **AgentModel / BackendModel** | `storage/models.py` | SQLAlchemy ORM models |
| **GatewaySettings** | `config.py` | Pydantic config models |

---

## Request Flow Example: `tools/list`

```mermaid
sequenceDiagram
    participant Client as Copilot
    participant GW as Gateway<br/>main.py
    participant Auth as OktaTokenValidator
    participant Router as ProxyHandler
    participant Exchanger as OktaCrossAppAccessManager
    participant Cache as TokenCache
    participant Okta as Okta<br/>Auth Server
    participant MCP as Backend<br/>Employee MCP

    Client->>GW: POST /employees<br/>tools/list<br/>+ Bearer Token
    
    GW->>Auth: Validate JWT
    Auth->>Auth: Check audience<br/>& signature
    Auth-->>GW: ✅ Valid token
    
    GW->>Router: proxy_request<br/>(method, token, agent)
    Router->>Router: Extract agent<br/>from X-MCP-Agent
    Router->>Router: Load agent config
    
    Router->>Exchanger: exchange_id_token<br/>_to_mcp_token
    Exchanger->>Cache: Check cache<br/>for token
    
    alt Cache Hit
        Cache-->>Exchanger: Return cached token
    else Cache Miss
        Exchanger->>Okta: STEP 1: ID-JAG<br/>token exchange
        Okta-->>Exchanger: ID-JAG token
        Exchanger->>Okta: STEP 3: Exchange<br/>for target token
        Okta-->>Exchanger: MCP access token
        Exchanger->>Cache: Store token
    end
    
    Exchanger-->>Router: Backend token
    Router->>MCP: POST /mcp<br/>tools/list<br/>+ Backend token
    MCP-->>Router: tools array
    
    Router->>Router: Format response<br/>as JSON-RPC
    Router-->>Client: JSON-RPC result<br/>with tools

```

---

## Configuration & Startup

```mermaid
graph LR
    A["config.yaml"] -->|Load| B["InMemoryBackendStore"]
    B -->|Parse YAML| C["Backends Table"]
    B -->|Parse YAML| D["Agents Table"]
    C -->|Register| E["BackendRouter"]
    D -->|Register| F["OktaTokenValidator"]
    E & F -->|Initialize| G["Gateway Ready"]
    G -->|Listen| H["Port 8000"]

    style A fill:#fff3e0
    style B fill:#f1f8e9
    style H fill:#e0f2f1
```

---

## Key Design Patterns

### 1. **Separation of Concerns**
- `main.py` = HTTP/MCP protocol handling
- `proxy/handler.py` = Business logic routing
- `auth/` = Token management
- `backends/` = Backend coordination

### 2. **Two Auth Methods**
- **OAuth (for Agents)**: Copilot, Claude, Cursor → Okta
- **Service Auth (for Backends)**: Gateway → Backend (static keys, basic auth, ID-JAG)

### 3. **Token Exchange Pipeline**
```
User ID Token (from Okta OAuth)
    ↓
[BackendRouter selects ID-JAG mode]
    ↓
[OktaCrossAppAccessManager does 4-step exchange]
    ↓
[Backend Token cached in TokenCache]
    ↓
[ProxyHandler adds token to backend request]
```

### 4. **Session Management**
- Gateway maintains MCP `Session-Id` with each backend
- Sessions cached per backend to avoid recreating
- Used for stateful MCP interactions

---

## File Structure

```
okta-agent-proxy/
├── main.py                              # Entry point, HTTP/FastMCP
├── config.py                            # Pydantic config models
├── auth/
│   ├── okta_validator.py               # JWT validation
│   ├── cross_app_access.py             # ID-JAG token exchange
│   ├── agent_authz.py                  # Agent access control
│   └── backend_auth.py                 # Backend auth coordination
├── backends/
│   └── router.py                        # Backend token & routing logic
├── cache/
│   └── token_cache.py                  # In-memory token caching
├── proxy/
│   ├── handler.py                       # Main request router
│   └── session_manager.py               # MCP session caching
├── middleware/
│   ├── auth.py                          # Bearer token extraction
│   ├── agent_extractor.py              # Agent identification
│   ├── logging.py                       # Request logging
│   └── mcp_transparent_proxy.py         # Protocol detection
├── storage/
│   ├── base.py                          # Abstract store interface
│   ├── in_memory.py                     # SQLite in-memory DB
│   └── models.py                        # SQLAlchemy ORM models
├── discovery/
│   ├── metadata_client.py              # RFC9728 discovery
│   └── backend_tools.py                # Tool discovery
└── metadata.py                          # Metadata response builders
```

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **HTTP Server** | `uvicorn` + `starlette` |
| **MCP Framework** | `fastmcp` |
| **Config** | `pydantic` + YAML |
| **Database** | SQLite (in-memory) |
| **JWT** | `python-jose` + `cryptography` |
| **HTTP Client** | `httpx` (async) |
| **Token Exchange** | `okta-ai-sdk` (ID-JAG) |

