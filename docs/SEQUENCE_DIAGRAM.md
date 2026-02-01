# Sequence Diagrams - Okta MCP Adapter Flow

## Complete Flow: Claude Code Agent to Employee MCP via Proxy

This diagram shows the complete request flow from Claude Code authentication through to accessing the Employee MCP resource.

```
participant ClaudeCode as Claude Code<br/>(Agent)
participant Okta as Okta IdP<br/>(dev-xxxxx.okta.com)
participant User as User<br/>(Approves login)
participant Proxy as Adapter<br/>(localhost:8000)
participant TargetOkta as Target Okta<br/>(cross-app)
participant EmployeeMCP as Employee MCP<br/>(Backend)

rect rgb(200, 220, 255)
  note over ClaudeCode, EmployeeMCP: Phase 1: User Authentication
  User->>ClaudeCode: Open Claude Code IDE
  ClaudeCode->>Okta: Step 1: Redirect to login<br/>client_id: 0oa_claude_code<br/>redirect_uri: http://localhost:8000/callback
  Okta->>User: Display login form
  User->>Okta: Enter credentials
  Okta->>User: Display MFA (if configured)
  User->>Okta: Complete MFA
  Okta->>ClaudeCode: Step 2: Return access_token<br/>+ refresh_token<br/>audience: 0oa_claude_code
  Note over ClaudeCode: Store tokens in memory
end

rect rgb(200, 255, 220)
  note over ClaudeCode, EmployeeMCP: Phase 2: Resource Discovery (RFC9728)
  ClaudeCode->>Proxy: GET /.well-known/oauth-protected-resource
  Proxy->>ClaudeCode: Return metadata:<br/>- authorization_servers: [list]<br/>- issuer: https://dev-xxxxx.okta.com<br/>- scopes_supported: [mcp:read, mcp:write]
  Note over ClaudeCode: Store authorization server URL
end

rect rgb(255, 240, 200)
  note over ClaudeCode, EmployeeMCP: Phase 3: MCP Request with Agent ID
  ClaudeCode->>Proxy: POST /employees<br/>Headers:<br/>  Authorization: Bearer <okta_access_token><br/>  X-Agent-ID: claude-code<br/>  Accept: application/json, text/event-stream<br/>Body:<br/>  {"jsonrpc": "2.0",<br/>   "id": "1",<br/>   "method": "resources/list",<br/>   "params": {}}
  
  rect rgb(230, 230, 230)
    note over Proxy: 3.1: Validate JWT
    Proxy->>Okta: Fetch JWKS (cached, 1-day TTL)
    Okta->>Proxy: Return signing keys
    Proxy->>Proxy: Validate signature
    Proxy->>Proxy: Check exp (expiration)
    Proxy->>Proxy: Verify aud (audience)
    Note over Proxy: ✓ JWT Valid<br/>claims: {sub: user123, aud: 0oa_claude_code, ...}
  end
  
  rect rgb(230, 230, 230)
    note over Proxy: 3.2: Extract & Authorize Agent
    Proxy->>Proxy: Extract X-Agent-ID: claude-code
    Proxy->>Proxy: Load agent config from store
    Note over Proxy: Agent config:<br/>- backend_access: [partners]<br/>- scopes: [mcp:read]
    Proxy->>Proxy: Check: /employees → backend 'employees'
    Proxy->>Proxy: Check: 'employees' in agent.backend_access?
    Note over Proxy: ✗ NOT AUTHORIZED<br/>Agent can only access: [partners]
  end
  
  Proxy->>ClaudeCode: 403 Forbidden<br/>{"error": "authorization_denied",<br/> "message": "Agent cannot access backend 'employees'",<br/> "details": {<br/>   "backend_requested": "employees",<br/>   "backends_allowed": ["partners"]<br/> }}
  Note over ClaudeCode: ✗ Request Blocked
end

rect rgb(255, 200, 200)
  note over ClaudeCode, EmployeeMCP: Phase 3b: CORRECTED - Access Allowed Backend
  ClaudeCode->>Proxy: POST /partners<br/>Headers:<br/>  Authorization: Bearer <okta_access_token><br/>  X-Agent-ID: claude-code<br/>Body: {...same JSON-RPC...}
  
  rect rgb(230, 230, 230)
    note over Proxy: 3b.1: Validate & Authorize (Success)
    Proxy->>Proxy: Validate JWT ✓
    Proxy->>Proxy: Load agent claude-code ✓
    Proxy->>Proxy: Check /partners → backend 'partners' ✓
    Proxy->>Proxy: 'partners' in [partners] ✓
    Note over Proxy: ✓ AUTHORIZED
  end
  
  rect rgb(230, 230, 230)
    note over Proxy: 3b.2: Determine Auth Method
    Proxy->>Proxy: Load backend config 'partners'
    Note over Proxy: Backend 'partners':<br/>- url: http://localhost:9002<br/>- auth_method: pre-shared-key<br/>- key: partner_api_key_123
  end
  
  rect rgb(230, 230, 230)
    note over Proxy: 3b.3: Forward Request to Backend
    Proxy->>EmployeeMCP: POST /partners<br/>Headers:<br/>  X-API-Key: partner_api_key_123<br/>  Content-Type: application/json<br/>Body: {...JSON-RPC...}
  end
  
  rect rgb(230, 230, 230)
    note over EmployeeMCP: 3b.4: Backend Processing
    EmployeeMCP->>EmployeeMCP: Validate API key ✓
    EmployeeMCP->>EmployeeMCP: Parse JSON-RPC method
    EmployeeMCP->>EmployeeMCP: Process: resources/list
    EmployeeMCP->>EmployeeMCP: Build response
  end
  
  EmployeeMCP->>Proxy: 200 OK<br/>{"jsonrpc": "2.0",<br/> "id": "1",<br/> "result": {<br/>   "resources": [<br/>     {<br/>       "uri": "partner://1",<br/>       "name": "Partner ABC",<br/>       "description": "..."<br/>     }<br/>   ]<br/> }}
  
  Proxy->>ClaudeCode: 200 OK (same response)
  Note over ClaudeCode: ✓ Display resources in IDE
end

rect rgb(200, 200, 255)
  note over ClaudeCode, EmployeeMCP: Phase 4: Token Exchange (Okta Cross-App Example)
  
  note over Proxy: Alternative: If backend uses Okta Cross-App
  
  Proxy->>Proxy: Check cache for<br/>user123:employees:claude-code
  Note over Proxy: Cache miss (first request or expired)
  
  Proxy->>Proxy: Step 1: Issue ID-JAG JWT<br/>- subject: user123<br/>- aud: target_auth_server<br/>- iss: 0oa_claude_code<br/>- signed with agent.private_key
  
  Proxy->>TargetOkta: Step 2: Exchange ID-JAG JWT<br/>POST /oauth2/v1/token<br/>grant_type: urn:ietf:params:oauth:grant-type:token-exchange<br/>subject_token: <ID-JAG JWT><br/>assertion: <agent_private_key_assertion>
  
  TargetOkta->>TargetOkta: Validate ID-JAG JWT signature
  TargetOkta->>TargetOkta: Check aud matches target server
  TargetOkta->>TargetOkta: Issue access token
  
  TargetOkta->>Proxy: 200 OK<br/>{"access_token": "target_token_xyz",<br/> "token_type": "Bearer",<br/> "expires_in": 3600}
  
  Proxy->>Proxy: Cache token<br/>key: user123:employees:claude-code<br/>value: target_token_xyz<br/>ttl: 3600s
  
  Proxy->>EmployeeMCP: Forward with backend token<br/>Authorization: Bearer target_token_xyz
end

rect rgb(255, 200, 220)
  note over ClaudeCode, EmployeeMCP: Phase 5: Token Expiration & Refresh
  
  alt Token Still Valid
    Note over Proxy: Subsequent requests<br/>use cached token
  else Token Expired (401)
    Proxy->>EmployeeMCP: Forward request<br/>Bearer <expired_token>
    EmployeeMCP->>Proxy: 401 Unauthorized
    Proxy->>Proxy: Invalidate cache entry
    Proxy->>TargetOkta: Exchange new ID-JAG JWT<br/>(using still-valid user token)
    TargetOkta->>Proxy: Return new backend token
    Proxy->>Proxy: Update cache
    Proxy->>EmployeeMCP: Retry request with new token
    EmployeeMCP->>Proxy: 200 OK
    Proxy->>ClaudeCode: Return response
  else Client Token Expired (401)
    Proxy->>ClaudeCode: 401 Unauthorized
    Note over ClaudeCode: Prompt user to re-authenticate
  end
end
```

## Simplified Flow: Happy Path

```
participant Agent as MCP Agent<br/>(Claude Code)
participant Proxy as Adapter
participant MCP as Backend MCP

Agent->>Proxy: Request<br/>Bearer token + X-Agent-ID
activate Proxy

Proxy->>Proxy: ✓ Validate JWT
Proxy->>Proxy: ✓ Authorize agent
Proxy->>Proxy: ✓ Get backend token

Proxy->>MCP: Forward request<br/>with auth headers
activate MCP
MCP->>MCP: Process
MCP->>Proxy: Response
deactivate MCP

Proxy->>Agent: Return response
deactivate Proxy
```

## Error Scenarios

### Scenario 1: Invalid Token Signature
```
Agent->>Proxy: Request<br/>Bearer <invalid_token>
Proxy->>Okta: Validate against JWKS
Okta->>Proxy: ✗ Signature invalid
Proxy->>Agent: 401 Unauthorized<br/>error: invalid_token
```

### Scenario 2: Token Expired
```
Agent->>Proxy: Request<br/>Bearer <expired_token>
Proxy->>Proxy: JWT valid? No (exp check)
Proxy->>Agent: 401 Unauthorized<br/>error: token_expired
Agent->>Proxy: (Triggers re-auth flow)
```

### Scenario 3: Agent Not Found
```
Agent->>Proxy: Request<br/>X-Agent-ID: unknown-agent
Proxy->>Proxy: Load agent config
Proxy->>Proxy: ✗ Agent not found
Proxy->>Agent: 403 Forbidden<br/>error: agent_not_found
```

### Scenario 4: Unauthorized Backend Access
```
Agent->>Proxy: Request<br/>X-Agent-ID: claude-code<br/>Path: /employees
Proxy->>Proxy: Check: employees in agent.backend_access?
Proxy->>Proxy: ✗ NOT in [partners]
Proxy->>Agent: 403 Forbidden<br/>error: authorization_denied
```

### Scenario 5: Backend Token Exchange Fails
```
Proxy->>TargetOkta: Exchange ID-JAG JWT
TargetOkta->>Proxy: ✗ Invalid assertion
Proxy->>Proxy: Invalidate cache
Proxy->>Agent: 401 Unauthorized<br/>error: token_exchange_failed
```

### Scenario 6: Backend Returns 401
```
Proxy->>MCP: Forward request<br/>Bearer <backend_token>
MCP->>Proxy: 401 Unauthorized
Proxy->>Proxy: Invalidate cache entry
Proxy->>Agent: 401 Unauthorized<br/>(propagate directly)
Note over Agent: Does NOT retry - user must re-auth
```

## Use Cases

### Use Case 1: Cursor Agent Accessing Employee Resource
- **Agent**: cursor
- **Path**: /employees
- **Authorization**: ✓ employees in backend_access
- **Auth Method**: okta-cross-app
- **Result**: ✓ Success

### Use Case 2: Claude Code Agent Accessing Partner Resource
- **Agent**: claude-code
- **Path**: /partners
- **Authorization**: ✓ partners in backend_access
- **Auth Method**: pre-shared-key
- **Result**: ✓ Success

### Use Case 3: Claude Code Agent Trying to Access Finance
- **Agent**: claude-code
- **Path**: /finance
- **Authorization**: ✗ NOT in backend_access
- **Result**: ✗ 403 Forbidden

### Use Case 4: Different User Same Agent
- **Agent**: cursor
- **Previous Token**: from_user_alice
- **New Request**: from_user_bob
- **Cache Key**: bob:employees:cursor
- **Result**: New token exchange (different user)

## Component Interactions

### Authorization Flow
```
Request arrives
  → Extract JWT
  → Validate signature (Okta JWKS)
  → Extract agent_id
  → Load agent config
  → Check backend in agent.backend_access
  → Proceed if ✓, deny if ✗
```

### Token Exchange Flow
```
Need backend token
  → Check cache hit?
  → If hit: use cached token
  → If miss:
    → Issue ID-JAG JWT (agent credentials)
    → Exchange at target auth server
    → Cache result (TTL: 3600s)
    → On 401: invalidate, retry once
    → Return error if still fails
```

### Request Forwarding Flow
```
Ready to forward
  → Select auth handler (3 methods)
  → Add auth headers
  → Forward JSON-RPC request
  → On 200: return response
  → On 401: invalidate cache, return error
  → On other: return error
```

