# Architecture Diagram - Okta MCP Adapter

## System Architecture

```mermaid
graph TB
    subgraph MCP_Clients["MCP Clients"]
        Cursor["🖥️ Cursor IDE<br/>(Agent: cursor)"]
        ClaudeCode["💻 Claude Code<br/>(Agent: claude-code)"]
        Copilot["🔵 Copilot<br/>(Agent: copilot)"]
    end

    subgraph Proxy["Okta MCP Adapter<br/>(port 8000)"]
        FastMCP["FastMCP Server<br/>Streamable HTTP"]
        
        subgraph Auth_Layer["Authentication Layer"]
            TokenVal["JWT Validator<br/>(Okta JWKS cache)"]
            AgentExt["Agent Extractor<br/>(X-Agent-ID header)"]
        end
        
        subgraph AuthZ_Layer["Authorization Layer"]
            AgentAuthZ["Agent Authorization<br/>(backend_access check)"]
            ScopeVal["Scope Validator<br/>(mcp:read/write)"]
        end
        
        subgraph Routing_Layer["Routing Layer"]
            Router["Backend Router<br/>(path-based)"]
            Discovery["Metadata Discovery<br/>(RFC9728)"]
        end
        
        subgraph TokenEx_Layer["Token Exchange Layer"]
            IdJagIssuer["ID-JAG Issuer<br/>(JWT creation)"]
            IdJagEx["ID-JAG Exchanger<br/>(Token exchange)"]
            TokenCache["Token Cache<br/>(TTL: 3600s)"]
        end
        
        subgraph Proxy_Layer["Proxy Layer"]
            AuthHandler["Auth Handlers<br/>Okta | APIKey | Basic"]
            ProxyReq["Request Forwarder<br/>(httpx async)"]
        end
        
        subgraph Storage_Layer["Storage Layer"]
            Store["Backend Config Store<br/>(SQLite in-memory)"]
            AgentStore["Agent Store<br/>(SQLite in-memory)"]
            AuditLog["Audit Log<br/>(SQLite in-memory)"]
        end
        
        subgraph Config["Configuration"]
            YamlFile["config.yaml<br/>(Backends + Agents)"]
            EnvFile[".env<br/>(Okta credentials)"]
        end
    end

    subgraph Okta["Okta Identity Provider"]
        OktaAuth["🔐 Okta Org<br/>(dev-XXXXX.okta.com)"]
        JWKS["JWKS Endpoint<br/>(Key rotation)"]
        OAuthServer["OAuth 2.1 Server<br/>(Token endpoint)"]
    end

    subgraph Backends["Target MCP Servers"]
        EmployeesMCP["👥 Employees MCP<br/>(Okta Cross-App)"]
        PartnersMCP["🤝 Partners MCP<br/>(Pre-Shared Key)"]
        FinanceMCP["💰 Finance MCP<br/>(Service Account)"]
    end

    %% Client to Proxy
    Cursor -->|"Bearer Token<br/>X-Agent-ID: cursor"| FastMCP
    ClaudeCode -->|"Bearer Token<br/>X-Agent-ID: claude-code"| FastMCP
    Copilot -->|"Bearer Token<br/>X-Agent-ID: copilot"| FastMCP

    %% Proxy Flow
    FastMCP --> TokenVal
    FastMCP --> AgentExt
    TokenVal --> AuthZ_Layer
    AgentExt --> AgentAuthZ
    AgentAuthZ --> ScopeVal
    ScopeVal --> Router
    Router --> Discovery
    Discovery --> TokenEx_Layer
    IdJagIssuer --> IdJagEx
    IdJagEx --> TokenCache
    TokenCache --> AuthHandler
    AuthHandler --> ProxyReq

    %% Storage
    Store --> YamlFile
    AgentStore --> YamlFile
    AuditLog --> EnvFile
    
    %% Auth to Okta
    TokenVal -->|"JWKS Request"| JWKS
    IdJagIssuer -->|"Token Exchange<br/>(RFC8693)"| OAuthServer
    IdJagEx -->|"Exchange ID-JAG JWT<br/>(RFC7523)"| OAuthServer

    %% Proxy to Backends
    ProxyReq -->|"Bearer Token"| EmployeesMCP
    ProxyReq -->|"X-API-Key"| PartnersMCP
    ProxyReq -->|"Basic Auth"| FinanceMCP

    %% Styling
    classDef client fill:#4A90E2,stroke:#2E5C8A,stroke-width:2px,color:#fff
    classDef adapter fill:#F5A623,stroke:#B86E1F,stroke-width:2px,color:#fff
    classDef auth fill:#7ED321,stroke:#5FA919,stroke-width:2px,color:#fff
    classDef storage fill:#BD10E0,stroke:#8B0AA8,stroke-width:2px,color:#fff
    classDef okta fill:#00B4D8,stroke:#0077B6,stroke-width:2px,color:#fff
    classDef backend fill:#E84C3D,stroke:#A63028,stroke-width:2px,color:#fff

    class Cursor,ClaudeCode,Copilot client
    class FastMCP,Router,ProxyReq adapter
    class TokenVal,AgentExt,AgentAuthZ,IdJagIssuer,IdJagEx auth
    class Store,AgentStore,AuditLog storage
    class OktaAuth,JWKS,OAuthServer okta
    class EmployeesMCP,PartnersMCP,FinanceMCP backend
```

## Data Flow

### 1. Request Layer
```
MCP Client
  ├─ Headers: Authorization: Bearer <okta_token>
  ├─ Headers: X-Agent-ID: cursor
  ├─ Headers: Accept: application/json, text/event-stream
  └─ Body: {"jsonrpc":"2.0","method":"tools/list",...}
```

### 2. Validation Layer
```
Proxy receives request
  ├─ Extract Bearer token
  ├─ Validate JWT signature (Okta JWKS)
  ├─ Check token expiration
  ├─ Verify audience
  ├─ Extract agent_id from header
  ├─ Load agent config from store
  └─ Verify agent enabled
```

### 3. Authorization Layer
```
  ├─ Check: backend in agent.backend_access?
  ├─ Check: agent has required scopes?
  └─ Deny with 403 if unauthorized
```

### 4. Token Exchange Layer
```
  ├─ Check token cache (key: user_id:backend_name:agent_id)
  ├─ If miss:
  │  ├─ Issue ID-JAG JWT (using agent credentials)
  │  ├─ Exchange at target auth server
  │  ├─ Cache result with TTL
  │  └─ On 401: invalidate cache, return error
  └─ Use cached token
```

### 5. Request Forwarding Layer
```
  ├─ Select auth handler (okta-cross-app|pre-shared-key|service-account)
  ├─ Add auth headers to backend request
  ├─ Forward JSON-RPC request
  ├─ Handle response (200|401|other)
  └─ Return to client
```

## Component Responsibilities

| Component | Responsibility |
|-----------|-----------------|
| **FastMCP Server** | HTTP transport, JSON-RPC handling |
| **JWT Validator** | Signature verification, token validation |
| **Agent Extractor** | Parse X-Agent-ID header, load config |
| **Agent AuthZ** | Check backend_access, scopes |
| **Backend Router** | Path-to-backend mapping, discovery |
| **ID-JAG Issuer** | Create ID-JAG JWT (agent credentials) |
| **ID-JAG Exchanger** | Exchange JWT for backend token |
| **Token Cache** | Reduce token exchange latency |
| **Auth Handlers** | Create auth headers (3 methods) |
| **Request Forwarder** | Send to backend, handle response |
| **Backend Store** | CRUD for backends, persistence |
| **Agent Store** | CRUD for agents, persistence |
| **Audit Log** | Track all changes |

## Security Boundaries

```
┌─────────────────────────────────────────┐
│         MCP Client (Cursor)             │
│        (May be compromised)             │
└─────────────────┬───────────────────────┘
                  │ Bearer Token + X-Agent-ID
                  ↓
┌─────────────────────────────────────────┐
│   ⚠️  SECURITY BOUNDARY #1             │
│   Proxy validates token signature       │
│   Checks against Okta JWKS              │
└─────────────────┬───────────────────────┘
                  │ Validated JWT claims
                  ↓
┌─────────────────────────────────────────┐
│   ⚠️  SECURITY BOUNDARY #2             │
│   Proxy checks agent authorization      │
│   Verifies backend_access list          │
└─────────────────┬───────────────────────┘
                  │ Authorized backend
                  ↓
┌─────────────────────────────────────────┐
│   ⚠️  SECURITY BOUNDARY #3             │
│   Proxy exchanges token for backend     │
│   Uses agent-specific credentials       │
└─────────────────┬───────────────────────┘
                  │ Backend token
                  ↓
┌─────────────────────────────────────────┐
│    Backend MCP Server (Trusted)         │
│   (Must validate token independently)   │
└─────────────────────────────────────────┘
```

## Multi-Agent Architecture

```
┌──────────────────────────────────────────────────────┐
│              Adapter Configuration                   │
├──────────────────────────────────────────────────────┤
│                                                      │
│  Agent: cursor                                       │
│  ├─ client_id: 0oa_cursor_app                       │
│  ├─ private_key: (PKCS8)                            │
│  ├─ scopes: [mcp:read, mcp:write]                   │
│  └─ backend_access: [employees, finance]            │
│                                                      │
│  Agent: claude-code                                  │
│  ├─ client_id: 0oa_claude_code                      │
│  ├─ private_key: (PKCS8)                            │
│  ├─ scopes: [mcp:read]                              │
│  └─ backend_access: [partners]                       │
│                                                      │
│  Backend: employees (Okta Cross-App)                │
│  ├─ url: http://localhost:9001                      │
│  ├─ paths: [/employees, /hr]                        │
│  └─ target auth server: target-okta.okta.com        │
│                                                      │
│  Backend: partners (Pre-Shared Key)                  │
│  ├─ url: http://localhost:9002                      │
│  ├─ paths: [/partners]                              │
│  └─ key: partner_api_key_123                         │
│                                                      │
└──────────────────────────────────────────────────────┘
```

## Token Exchange Flow (ID-JAG)

```mermaid
sequenceDiagram
    participant Agent as MCP Agent<br/>(cursor)
    participant Adapter as Adapter
    participant TargetAuth as Target Auth Server
    participant Backend as Backend MCP
    
    Agent->>Adapter: Bearer <okta_token>
    activate Adapter
    
    Adapter->>Adapter: Validate JWT
    Adapter->>Adapter: Load agent config (cursor)
    Adapter->>Adapter: Check backend access
    
    alt Token in cache
        Adapter->>Adapter: Use cached token
    else Cache miss
        Adapter->>TargetAuth: Step 1: Issue ID-JAG JWT<br/>(RFC8693)<br/>subject: user<br/>aud: target_auth_server<br/>signed with agent.private_key
        TargetAuth->>TargetAuth: Validate ID-JAG JWT
        
        Adapter->>TargetAuth: Step 2: Exchange ID-JAG<br/>for access token<br/>(RFC7523)
        TargetAuth->>Adapter: Return backend token
        Adapter->>Adapter: Cache token (TTL: 3600s)
    end
    
    deactivate Adapter
    
    Adapter->>Backend: Forward with backend token
    activate Backend
    Backend->>Backend: Validate token
    Backend->>Backend: Process request
    Backend->>Adapter: Return response
    deactivate Backend
    
    Adapter->>Agent: Agent receives tokens<br/>& can use access_token<br/>for MCP tool calls
```

---

## Frontend Login Flow: Agent Authentication via Adapter Discovery

**Key Pattern**: Adapter proxies Okta discovery metadata and provides its own Dynamic Client Registration (DCR) endpoint with pre-configured agent credentials.

```mermaid
sequenceDiagram
    participant Agent as Claude Code<br/>MCP Agent
    participant Browser as Browser<br/>OAuth Redirect
    participant Adapter as Okta MCP Adapter<br/>Discovery + DCR
    participant DCREndpoint as Adapter DCR<br/>/oauth2/register
    participant OktaDisc as Okta Discovery<br/>/.well-known/oauth-*
    participant AuthzServer as Okta<br/>Authorization Server
    participant Token as Okta<br/>Token Endpoint

    Agent->>Adapter: 1. Fetch adapter discovery metadata<br/>GET /.well-known/oauth-authorization-server
    
    Adapter->>OktaDisc: (Proxy) Fetch Okta metadata<br/>for authorization_server endpoints
    
    OktaDisc-->>Adapter: Returns Okta metadata:<br/>- authorize_endpoint (Okta)<br/>- token_endpoint (Okta)<br/>- jwks_uri (Okta)
    
    Adapter->>Adapter: Enhance metadata:<br/>- Add registration_endpoint<br/>(points to adapter DCR)
    
    Adapter-->>Agent: Returns enhanced metadata:<br/>- Okta OAuth endpoints<br/>- Adapter DCR endpoint
    
    Agent->>DCREndpoint: 2. Register/get pre-configured credentials<br/>POST /oauth2/register<br/>(agent_name or client_assertion)
    
    DCREndpoint->>DCREndpoint: Lookup pre-configured<br/>agent in config.yaml<br/>or admin-configured agents
    
    DCREndpoint-->>Agent: Returns:<br/>- client_id (pre-configured)<br/>- client_secret (or empty)
    
    Agent->>Agent: Generate PKCE code<br/>& state parameter
    
    Agent->>Browser: 3. Redirect to Okta authorization<br/>GET https://okta.../oauth2/authorize?<br/>client_id, redirect_uri,<br/>scope, state, code_challenge
    
    Browser->>AuthzServer: User authentication & consent
    AuthzServer-->>Browser: Authorization code
    
    Browser->>Adapter: 4. Redirect callback to adapter<br/>GET /oauth2/callback?code&state
    
    Adapter->>Token: Exchange authorization code<br/>POST https://okta.../oauth2/v1/token<br/>code, client_id, client_secret,<br/>code_verifier (PKCE)
    
    Token-->>Adapter: Returns:<br/>- access_token (JWT)<br/>- id_token<br/>- refresh_token
    
    Adapter->>Adapter: Validate JWT signature<br/>using Okta JWKS
    
    Adapter-->>Browser: 5. Redirect with tokens<br/>(or store in secure context)
    
    Browser->>Agent: Agent receives tokens<br/>& can use access_token<br/>for MCP tool calls
```

**Why This Pattern?**
- ✅ **Pre-configured credentials**: Agents don't need dynamic registration with Okta
- ✅ **Centralized management**: Config defined in adapter (config.yaml)
- ✅ **Enhanced discovery**: Adapter adds its own DCR endpoint to Okta's metadata
- ✅ **Single adapter URL**: Agents only need adapter URL, not Okta URL
- ✅ **Transparent OAuth**: Actual OAuth still happens with Okta (authorize/token endpoints)

---

## Request Flow Example: `tools/list`

```mermaid
sequenceDiagram
    participant Client as Copilot
    participant GW as Okta MCP Adapter<br/>main.py
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

