# Okta Agent Proxy - Admin API Documentation

## Overview

The Admin API provides secure endpoints for managing agents and backends in the Okta Agent Proxy. All admin endpoints are protected with JWT token authentication.

**Base URL:** `http://localhost:8000/api/admin`

## Authentication

### Login Endpoint

Get an admin JWT token.

```
POST /api/admin/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### Using the Token

Include the token in all subsequent requests:

```
Authorization: Bearer <access_token>
```

**Token Expiration:** 1 hour (3600 seconds)

---

## Agent Management

### List All Agents

```
GET /api/admin/agents
Authorization: Bearer <token>
```

**Response:**
```json
{
  "agents": [
    {
      "agent_name": "claude-code",
      "agent_id": "wlpu1ohuuexps8K5X1d7",
      "client_id": "0oau1oq70sOZqDrxl1d7",
      "private_key": "{ \"kty\": \"RSA\", ... }",
      "scopes": ["openid", "offline_access"],
      "backend_access": ["employees", "partners"],
      "enabled": true
    }
  ]
}
```

### Create Agent

```
POST /api/admin/agents
Authorization: Bearer <token>
Content-Type: application/json

{
  "agent_name": "new-agent",
  "agent_id": "service-account-id",
  "client_id": "oauth-client-id",
  "private_key": "{ \"kty\": \"RSA\", ... }",
  "scopes": ["openid"],
  "backend_access": ["employees"],
  "enabled": true
}
```

**Response:** (201 Created)
```json
{
  "agent_name": "new-agent",
  "agent_id": "service-account-id",
  "client_id": "oauth-client-id",
  "private_key": "{ \"kty\": \"RSA\", ... }",
  "scopes": ["openid"],
  "backend_access": ["employees"],
  "enabled": true
}
```

### Update Agent

```
PUT /api/admin/agents/{name}
Authorization: Bearer <token>
Content-Type: application/json

{
  "backend_access": ["employees", "hr"],
  "enabled": false
}
```

**Response:** (200 OK)
```json
{
  "agent_name": "claude-code",
  "agent_id": "wlpu1ohuuexps8K5X1d7",
  "client_id": "0oau1oq70sOZqDrxl1d7",
  "private_key": "{ \"kty\": \"RSA\", ... }",
  "scopes": ["openid", "offline_access"],
  "backend_access": ["employees", "hr"],
  "enabled": false
}
```

### Delete Agent

```
DELETE /api/admin/agents/{name}
Authorization: Bearer <token>
```

**Response:** (200 OK)
```json
{
  "message": "Agent 'claude-code' deleted"
}
```

---

## Backend Management

### List All Backends

```
GET /api/admin/backends
Authorization: Bearer <token>
```

**Response:**
```json
{
  "backends": [
    {
      "backend_name": "employees",
      "url": "http://localhost:8001/mcp",
      "auth_method": "okta-cross-app",
      "auth_config": {
        "id_jag_mode": "static",
        "target_authorization_server": "https://domain.okta.com/oauth2/aussXXXX",
        "target_audience": "mcp_resource_server"
      },
      "enabled": true
    }
  ]
}
```

### Create Backend

```
POST /api/admin/backends
Authorization: Bearer <token>
Content-Type: application/json

{
  "backend_name": "hr-system",
  "url": "http://localhost:8002/mcp",
  "auth_method": "okta-cross-app",
  "auth_config": {
    "id_jag_mode": "static",
    "target_authorization_server": "https://domain.okta.com/oauth2/aussXXXX",
    "target_audience": "hr_resource_server"
  },
  "enabled": true
}
```

**Response:** (201 Created)

### Update Backend

```
PUT /api/admin/backends/{name}
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": "http://localhost:8001/new-path",
  "enabled": false
}
```

**Response:** (200 OK)

### Delete Backend

```
DELETE /api/admin/backends/{name}
Authorization: Bearer <token>
```

**Response:** (200 OK)
```json
{
  "message": "Backend 'employees' deleted"
}
```

---

## Authentication Methods

### 1. Okta Cross-App (ID-JAG)

```json
{
  "auth_method": "okta-cross-app",
  "auth_config": {
    "id_jag_mode": "static",
    "target_authorization_server": "https://domain.okta.com/oauth2/auss...",
    "target_audience": "mcp_resource_server"
  }
}
```

### 2. Pre-shared Key (API Key)

```json
{
  "auth_method": "pre-shared-key",
  "auth_config": {
    "key": "your-api-key",
    "header_name": "X-API-Key"
  }
}
```

### 3. Service Account (Basic Auth)

```json
{
  "auth_method": "service-account",
  "auth_config": {
    "username": "service-account-id",
    "password": "service-account-secret"
  }
}
```

---

## Error Responses

### 401 Unauthorized (Missing or Invalid Token)

```json
{
  "error": "unauthorized",
  "message": "Missing or invalid admin token"
}
```

### 400 Bad Request (Invalid Input)

```json
{
  "error": "invalid_input",
  "message": "Missing required field: client_id"
}
```

### 404 Not Found

```json
{
  "error": "not_found",
  "message": "Agent 'non-existent' not found"
}
```

### 500 Internal Server Error

```json
{
  "error": "server_error",
  "message": "Failed to create agent"
}
```

---

## Configuration Management

### How It Works

1. **Admin logs in** via `/api/admin/login` → receives JWT token
2. **Admin makes API calls** with token in Authorization header
3. **Gateway validates token** and checks admin role
4. **Config is modified** in `config.yaml`
5. **In-memory store is reloaded** with new configuration
6. **Action is logged** with timestamp and admin username

### Backup & Recovery

- **Automatic backups** created at `config.yaml.bak` before each write
- **Changes logged** with full details in gateway logs
- **Rollback**: Manually restore from `.bak` file if needed

---

## Security Features

| Feature | Details |
|---------|---------|
| **Token Expiration** | 1 hour (configurable) |
| **Token Secret** | Environment variable `ADMIN_JWT_SECRET` |
| **Rate Limiting** | Not yet implemented (recommended for production) |
| **Audit Logging** | All admin actions logged with timestamp |
| **Credentials** | Environment variables `ADMIN_USERNAME`, `ADMIN_PASSWORD` |
| **HTTPS** | Recommended for production |
| **Separate Port** | Optional: Run admin API on different port |

---

## Environment Variables

```bash
# Admin authentication
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_JWT_SECRET=your-super-secret-key-change-in-production
ADMIN_TOKEN_EXPIRATION=3600  # 1 hour

# Config file path
CONFIG_PATH=config/config.yaml
```

---

## Integration with Admin UI

The Next.js Admin UI (`okta_agent_proxy_admin`) uses these endpoints:

1. **Login**: `POST /api/admin/login` with hardcoded credentials
2. **List**: `GET /api/admin/agents` and `/api/admin/backends`
3. **Create**: `POST /api/admin/agents` and `/api/admin/backends`
4. **Update**: `PUT /api/admin/agents/{name}` and `/api/admin/backends/{name}` (UI ready)
5. **Delete**: `DELETE /api/admin/agents/{name}` and `/api/admin/backends/{name}`

**Flow:**
```
UI (/login) 
  ↓ (credentials) 
→ /api/admin/login (get JWT token)
  ↓ (token in Authorization header)
→ /api/admin/agents (CRUD operations)
  ↓ (config.yaml written)
→ Config Manager (reloads store)
  ↓ 
→ Gateway ready with new config
```

---

## Example cURL Commands

### Login

```bash
curl -X POST http://localhost:8000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### List Agents

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.access_token')

curl -X GET http://localhost:8000/api/admin/agents \
  -H "Authorization: Bearer $TOKEN"
```

### Create Agent

```bash
curl -X POST http://localhost:8000/api/admin/agents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "test-agent",
    "agent_id": "test-id",
    "client_id": "test-client",
    "private_key": "{}",
    "backend_access": ["employees"],
    "enabled": true
  }'
```

---

## Troubleshooting

### Token Validation Fails

- Check token hasn't expired (1 hour)
- Verify `ADMIN_JWT_SECRET` matches between requests
- Check `Authorization` header format: `Bearer <token>`

### Changes Not Appearing

- Config Manager reloads in-memory store automatically
- Restart gateway if needed: `python -m okta_agent_proxy.main`
- Check `config.yaml` was modified: `cat config.yaml`

### Admin Login Fails

- Verify credentials match environment variables
- Check logs for failed login attempts
- Use default: username=`admin`, password=`admin123`

---

**Last Updated:** 2026-01-25
**Version:** 1.0.0
