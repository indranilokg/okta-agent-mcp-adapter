# Okta MCP Adapter - Architecture

## System Overview

```mermaid
%%{init: {'flowchart': {'htmlLabels': true, 'curve': 'linear'}, 'theme': 'base', 'primaryColor': '#e1f5ff', 'primaryTextColor': '#000', 'fontSize': '18px'}}%%
graph TB
    subgraph Clients["🔐 Clients"]
        Cursor["<b>Cursor</b><br/>VSCode"]
        Claude["<b>Claude</b>"]
        Copilot["<b>Copilot</b>"]
    end

    subgraph Adapter["🌐 Okta MCP Adapter"]
        Main["<b>main.py</b><br/>Entry Point"]
        
        subgraph Auth["🔑 Authentication"]
            OAuthDisc["<b>OAuth Discovery</b><br/>/.well-known/oauth-*"]
            DCR["<b>DCR</b><br/>/oauth2/register"]
            TokenEP["<b>Token EP</b><br/>/oauth2/v1/token"]
            Validator["<b>Validator</b><br/>JWT validation"]
        end
        
        subgraph Routing["📍 Routing"]
            Middleware["<b>Auth Middleware</b>"]
            ProxyHandler["<b>ProxyHandler</b>"]
            SessionMgr["<b>SessionManager</b>"]
        end
        
        subgraph Exchange["🔄 Token Exchange"]
            CrossApp["<b>CrossApp</b><br/>ID-JAG"]
            BackendRouter["<b>BackendRouter</b>"]
            Cache["<b>TokenCache</b>"]
        end
        
        subgraph Discovery["🔍 Discovery"]
            MetadataClient["<b>MetadataClient</b>"]
            AuthzClient["<b>ToolsDiscovery</b>"]
        end
        
        subgraph Storage["💾 Config"]
            Store["<b>BackendStore</b>"]
            Config["<b>config.yaml</b>"]
        end
    end

    subgraph Backends["🛠️ Backend MCP"]
        Employees["<b>Employee MCP</b>"]
        Partners["<b>Partner MCP</b>"]
    end

    subgraph Okta["☁️ Okta"]
        AuthServer["<b>Auth Server</b>"]
        JWKS["<b>JWKS</b>"]
    end

    Cursor -->|OAuth| OAuthDisc
    Claude -->|OAuth| OAuthDisc
    Copilot -->|OAuth| OAuthDisc
    
    OAuthDisc --> TokenEP
    DCR --> Config
    TokenEP --> Validator
    TokenEP -->|token| CrossApp
    
    Clients -->|tools/list| Middleware
    Middleware --> ProxyHandler
    ProxyHandler -->|config| Store
    ProxyHandler -->|exchange| BackendRouter
    
    BackendRouter -->|manager| CrossApp
    CrossApp -->|ID-JAG| AuthServer
    CrossApp -->|cache?| Cache
    Cache -->|verify| JWKS
    
    ProxyHandler -->|session| SessionMgr
    SessionMgr -->|request| Employees
    
    ProxyHandler -->|discovery| MetadataClient
    ProxyHandler -->|tools| AuthzClient
    
    Config -->|load| Store
    Store -->|query| BackendRouter
    
    Employees -->|response| SessionMgr
    SessionMgr -->|JSON-RPC| Clients
    
    AuthServer -->|tokens| Cache
    JWKS -->|keys| Validator
    
    style Adapter fill:#e1f5ff,stroke:#0288d1,stroke-width:3px,font-size:16px
    style Auth fill:#fff3e0,stroke:#f57c00,stroke-width:2px,font-size:15px
    style Routing fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,font-size:15px
    style Exchange fill:#e8f5e9,stroke:#388e3c,stroke-width:2px,font-size:15px
    style Discovery fill:#fce4ec,stroke:#c2185b,stroke-width:2px,font-size:15px
    style Storage fill:#f1f8e9,stroke:#689f38,stroke-width:2px,font-size:15px
    style Okta fill:#ffe0b2,stroke:#f57f17,stroke-width:2px,font-size:15px
    style Clients fill:#e0f2f1,stroke:#00796b,stroke-width:2px,font-size:15px
    style Backends fill:#f5f5f5,stroke:#424242,stroke-width:2px,font-size:15px
```

---

## Component Details

### 🔑 Authentication Layer (`auth/`)

| Component | File | Purpose |
|-----------|------|---------|
| **OktaTokenValidator** | `okta_validator.py` | JWT validation, JWKS caching, audience checking |
| **OktaCrossAppAccessManager** | `cross_app_access.py` | ID-JAG token exchange (RFC8693) using Okta AI SDK |
| **OAuth Endpoints** | `main.py` | Discovery proxy, DCR endpoint, authorize, token endpoints |

**Discovery Proxy Pattern**:
- Adapter proxies Okta's `.well-known/oauth-authorization-server` metadata
- Adds `registration_endpoint` pointing to adapter's `/oauth2/register` (DCR)
- Adapter's DCR endpoint returns pre-configured `client_id` from `config.yaml`
- Agents use adapter URL for discovery, but OAuth happens with Okta (authorize/token endpoints from metadata)

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
| **AdapterSettings** | `config.py` | Pydantic config models |

---

## Configuration & Startup

```mermaid
graph LR
    A["config.yaml"] -->|Load| B["InMemoryBackendStore"]
    B -->|Parse YAML| C["Backends Table"]
    B -->|Parse YAML| D["Agents Table"]
    C -->|Register| E["BackendRouter"]
    D -->|Register| F["OktaTokenValidator"]
    E & F -->|Initialize| G["Adapter Ready"]
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

### 2. **Discovery Proxy with Pre-configured DCR**

The adapter acts as a discovery proxy and DCR provider:

```
Agent discovers adapter:  /.well-known/oauth-authorization-server
                ↓
Adapter proxies Okta metadata + adds DCR endpoint
                ↓
Agent calls adapter DCR:  /oauth2/register
                ↓
Adapter returns pre-configured client_id from config.yaml
                ↓
Agent uses Okta endpoints (from metadata) with pre-configured client_id
```

**Benefits:**
- ✅ Agents only know about adapter URL
- ✅ Credentials centrally managed in config.yaml / Admin UI
- ✅ No need for dynamic registration with Okta
- ✅ OAuth still happens with Okta (transparent to agents)

### 3. **Two Auth Methods**
- **OAuth (for Agents)**: Copilot, Claude, Cursor → Okta
- **Service Auth (for Backends)**: Adapter → Backend (static keys, basic auth, ID-JAG)

### 4. **Token Exchange Pipeline**
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

### 5. **Session Management**
- Adapter maintains MCP `Session-Id` with each backend
- Sessions cached per backend to avoid recreating
- Used for stateful MCP interactions

---

## File Structure

```
okta-mcp-adapter/
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

