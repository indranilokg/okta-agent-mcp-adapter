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

---

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

## Frontend Login Flow: Agent Authentication via Adapter Discovery (BFF Pattern)

**Key Pattern**: Adapter acts as Backend-for-Frontend (BFF), proxying Okta discovery and intercepting the token endpoint. Agents only interact with adapter URLs, not Okta directly.

```mermaid
sequenceDiagram
    participant Agent as Claude Code<br/>MCP Agent
    participant Browser as Browser<br/>OAuth Redirect
    participant Adapter as Okta MCP Adapter<br/>BFF Pattern
    participant OktaAuth as Okta<br/>Authorization Server
    participant OktaToken as Okta<br/>Token Endpoint (hidden)

    Agent->>Adapter: 1. Fetch discovery metadata<br/>GET /.well-known/oauth-authorization-server
    
    Adapter->>OktaAuth: (Proxy) Fetch Okta metadata
    OktaAuth-->>Adapter: Returns Okta endpoints
    
    Adapter->>Adapter: Enhance metadata:<br/>- authorize_endpoint: okta.../authorize<br/>- token_endpoint: adapter/oauth2/v1/token<br/>- registration_endpoint: adapter/register<br/>- jwks_uri: okta.../keys
    
    Adapter-->>Agent: Returns enhanced metadata<br/>(adapter is the only URL agent sees)
    
    Agent->>Adapter: 2. Get pre-configured credentials<br/>POST /oauth2/register?agent=claude-code
    
    Adapter->>Adapter: Lookup agent in config.yaml
    Adapter-->>Agent: Returns pre-configured:<br/>- client_id (from config.yaml)<br/>- redirect_uris
    
    Agent->>Agent: Generate PKCE code & state
    
    Agent->>Browser: 3. Redirect to OKTA authorize<br/>(endpoint from metadata)
    
    Browser->>OktaAuth: User authentication & consent
    OktaAuth-->>Browser: Authorization code<br/>redirect to redirect_uri
    
    Browser->>Agent: 4. Redirect callback to AGENT<br/>GET http://localhost:*/callback?code&state<br/>(redirect_uri = agent's local endpoint)
    
    Agent->>Adapter: 5. Exchange auth code at ADAPTER<br/>POST /oauth2/v1/token<br/>(token_endpoint from metadata)<br/>code, client_id, redirect_uri, code_verifier
    
    Adapter->>OktaToken: (Backend-for-Frontend)<br/>Exchange code at Okta<br/>(Agent uses adapter token endpoint)<br/>Adapter proxies to Okta
    
    OktaToken-->>Adapter: Returns tokens
    
    Adapter->>Adapter: Validate JWT signature<br/>using Okta JWKS
    
    Adapter-->>Agent: 6. Return tokens to agent<br/>- access_token (ID token for ID-JAG)<br/>- refresh_token<br/>- id_token
```

**BFF Pattern Benefits:**
- ✅ **Adapter controls token exchange**: Can add logging, security checks, token transformation
- ✅ **Hidden Okta complexity**: Agents only see adapter URLs
- ✅ **Pre-configured credentials**: DCR returns client_id from config.yaml
- ✅ **Single entry point**: All OAuth flows go through adapter
- ✅ **Security**: Adapter can validate, filter, and transform tokens

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
