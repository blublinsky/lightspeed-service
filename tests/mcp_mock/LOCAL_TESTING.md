# Local Testing Guide - MCP Client Headers (PR2)

This guide walks through testing the MCP client headers feature locally with the mock MCP server.

## Overview

We'll test three authentication patterns:
1. **File-based auth** - Static token from file
2. **Kubernetes auth** - User's k8s token passed through
3. **Client auth** - Client-provided headers (PR2 feature!)

## Prerequisites Setup

If you haven't set up OLS locally yet, follow these steps:

### 1. Install Dependencies

OLS requires Python 3.11+ and uses PDM for package management:

```bash
# Install PDM if you don't have it
curl -sSL https://pdm-project.org/install-pdm.py | python3 -

# Or with pip
pip install --user pdm

# Verify installation
pdm --version  # Should show 2.25.9 or higher
```

### 2. Clone and Install OLS

```bash
# If not already cloned
cd /Users/boris/Projects/
git clone https://github.com/openshift/lightspeed-service.git
cd lightspeed-service

# Install all dependencies (this takes a few minutes)
make install-deps

# Verify installation
make verify  # Should pass all checks
```

**What `make install-deps` does:**
- Creates a Python virtual environment (.venv)
- Installs all dependencies via PDM
- Sets up development tools (black, ruff, mypy, etc.)

**Verify installation worked:**
```bash
# Check Python version
python3 --version  # Should show 3.11.x or 3.12.x

# Check PDM is working
pdm --version

# Check dependencies are installed
pdm list | head -20

# Optional: Run tests to verify everything works
# make test-unit  # Takes ~30 seconds, not required for MCP testing
```

**If you see errors:**
- "uv not found" → Install uv (step 1)
- "Python version mismatch" → uv will automatically use the correct version
- "Permission denied" → Check file permissions on the repo

---

## Now Ready for MCP Testing

Once the above setup is complete, you're ready to test MCP client headers!

## Step 1: Start Mock MCP Server

Open **Terminal 1** and start the mock server:

```bash
cd /Users/boris/Projects/lightspeed-service

# Create test secret file
echo "Bearer test-secret-token-123" > /tmp/mcp-test-token

# Start mock server on port 3000
uv run python3 tests/mcp_mock/server.py 3000
```

You should see:
```
======================================================================
MCP Mock Server starting with HTTP and HTTPS
======================================================================
HTTP:  http://localhost:3000
HTTPS: https://localhost:3001
...
```

**Leave this terminal running** - you'll see request logs here.

## Step 2: Create Test OLS Config

Create a test config file with a complete, working OLS configuration.

**Create file:** `tests/mcp_mock/test-olsconfig.yaml`

```yaml
# Complete OLS config for MCP testing
# Based on scripts/olsconfig.yaml with MCP servers added
---
llm_providers:
  # Minimal provider config - won't actually be used for MCP header tests
  - name: test_provider
    type: watsonx
    url: "http://wont-be-used-for-mcp-tests"
    project_id: 00000000-0000-0000-0000-000000000000
    models:
      - name: test-model

ols_config:
  # Conversation cache (in-memory for testing)
  conversation_cache:
    type: memory
    memory:
      max_entries: 1000
  
  # Logging configuration
  logging_config:
    app_log_level: info
    lib_log_level: warning
    uvicorn_log_level: info
  
  # Default LLM (required but won't be called)
  default_provider: test_provider
  default_model: test-model
  
  # Disable query validation for simpler testing
  query_validation_method: disabled

# Dev configuration - disable auth/TLS for local testing
dev_config:
  enable_dev_ui: false
  disable_auth: true
  disable_tls: true

# MCP Servers - Three auth patterns to test
mcp_servers:
  # Test 1: File-based authentication (static token from file)
  - name: mock-file-auth
    url: http://localhost:3000
    headers:
      Authorization: /tmp/mcp-test-token
  
  # Test 2: Kubernetes authentication (user's k8s token passthrough)
  - name: mock-k8s-auth
    url: http://localhost:3000
    headers:
      Authorization: kubernetes
  
  # Test 3: Client-provided authentication (PR2 feature!)
  - name: mock-client-auth
    url: http://localhost:3000
    headers:
      Authorization: client
```

**Save this file as:** `tests/mcp_mock/test-olsconfig.yaml`

**Why this config works:**
- ✅ Uses OpenAI API (gpt-4o-mini model)
- ✅ In-memory cache (no database needed)
- ✅ `noop-with-token` auth (allows testing kubernetes placeholder)
- ✅ TLS disabled (dev_config)
- ✅ Query validation disabled (faster testing)
- ✅ Three MCP servers with different auth patterns

**Important:** You need a valid OpenAI API key in `/tmp/test-openai-key`!

## Step 3: Create Required Credential Files

Create the credential files that OLS needs:

```bash
# Create test MCP token (for mock-file-auth server)
echo "Bearer test-secret-token-123" > /tmp/mcp-test-token

# Create OpenAI API key file - REPLACE WITH YOUR ACTUAL KEY!
echo "sk-YOUR-ACTUAL-OPENAI-API-KEY-HERE" > /tmp/test-openai-key
```

**Note:** Replace `sk-YOUR-ACTUAL-OPENAI-API-KEY-HERE` with your real OpenAI API key from https://platform.openai.com/api-keys

## Step 4: Start OLS with Test Config

Open **Terminal 2** and start OLS:

```bash
cd /Users/boris/Projects/lightspeed-service

# Set config file path
export OLS_CONFIG_FILE=tests/mcp_mock/test-olsconfig.yaml

# Start OLS with uv
uv run python runner.py
```

Wait for OLS to start. You should see:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8080 (Press CTRL+C to quit)
```

**Expected warnings (can be ignored):**
- You may see warnings about LLM provider not being reachable
- This is OK - we're only testing MCP headers, not actual LLM calls
- As long as OLS starts and listens on port 8080, you're good to go

**If OLS fails to start:**
- Check that both credential files exist: `/tmp/mcp-test-token` and `/tmp/test-openai-key`
- Verify the config file path is correct
- Check OLS logs for specific error messages

**Leave this terminal running.**

**Common startup issues:**
- **LLM warnings**: You may see "LLM provider not ready" warnings - this is expected and OK
- **Port already in use**: Stop any other OLS instances with `pkill -f "make run"`
- **Config validation errors**: Check that both credential files exist in `/tmp/`
- **Missing credentials**: Verify `/tmp/test-openai-key` and `/tmp/mcp-test-token` were created

## Step 5: Test Discovery Endpoint

Open **Terminal 3** for testing:

```bash
# Test the discovery endpoint
curl -s http://localhost:8080/v1/mcp/client-auth-headers \
  -H "Authorization: Bearer test-user-token" | jq
```

**Expected output:**
```json
{
  "servers": [
    {
      "server_name": "mock-client-auth",
      "required_headers": ["Authorization"]
    }
  ]
}
```

✅ **What this proves:** Only `mock-client-auth` requires client headers (has `_client_` placeholder).

## Step 6: Test Query Without Client Headers

Test a query **without** providing client headers:

```bash
curl -s -X POST http://localhost:8080/v1/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user-k8s-token-123" \
  -d '{
    "query": "What tools are available?"
  }' | jq -r '.response'
```

**Check Terminal 1 (mock server logs):**

You should see **TWO** requests:
1. From `mock-file-auth` with header: `Authorization: Bearer test-secret-token-123`
2. From `mock-k8s-auth` with header: `Authorization: Bearer user-k8s-token-123`

You should **NOT** see a request from `mock-client-auth` (missing required headers).

**Verify captured headers:**
```bash
curl -s http://localhost:3000/debug/requests | jq
```

✅ **What this proves:** Servers without client headers are contacted. Servers requiring client headers are skipped (graceful degradation).

## Step 6b: Test Tool Invocation

Test that the LLM can actually **invoke** an MCP tool:

```bash
curl -s -X POST http://localhost:8080/v1/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user-k8s-token-123" \
  -d '{
    "query": "send hello world using mock_tool_file"
  }' | jq '.'
```

**Expected response:** The response should contain `tool_calls` and `tool_results`:
```json
{
  "tool_calls": [
    {
      "name": "mock_tool_file",
      "args": {"message": "Hello, World!"},
      "type": "tool_call"
    }
  ],
  "tool_results": [
    {
      "status": "success",
      "content": "Tool executed successfully with args: {'message': 'Hello, World!'}"
    }
  ]
}
```

✅ **What this proves:** The MCP tool is discovered via ToolsRAG filtering, passed to the LLM, and the LLM successfully invokes it end-to-end.

## Step 6c: Test Server Filtering (PR3 Feature!)

This verifies that tools from client-auth servers are **only visible when client headers are provided**.

### Test 1: Invoke client tool WITH client headers (should succeed)

```bash
curl -s -X POST http://localhost:8080/v1/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user-k8s-token-123" \
  -d '{
    "query": "send hello world using mock_tool_client",
    "mcp_headers": {"mock-client-auth": {"Authorization": "Bearer my-client-token-456"}}
  }' | jq '.'
```

**Expected response:** `mock_tool_client` is found and invoked successfully:
```json
{
  "tool_calls": [
    {
      "name": "mock_tool_client",
      "args": {"message": "Hello, World!"},
      "type": "tool_call"
    }
  ],
  "tool_results": [
    {
      "status": "success",
      "content": "Tool executed successfully with args: {'message': 'Hello, World!'}"
    }
  ]
}
```

### Test 2: Invoke client tool WITHOUT client headers (should fail to find tool)

```bash
curl -s -X POST http://localhost:8080/v1/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user-k8s-token-123" \
  -d '{
    "query": "send hello world using mock_tool_client"
  }' | jq '.'
```

**Expected response:** No tool calls - the LLM cannot find `mock_tool_client`:
```json
{
  "tool_calls": [],
  "tool_results": []
}
```

✅ **What this proves:** Server filtering works correctly. Client-auth server tools are only available when the corresponding `mcp_headers` are provided. Without them, the tools are filtered out by ToolsRAG, preventing unauthorized tool access.

## Step 7: Test Query WITH Client Headers (PR2 Feature!)

Now test with client-provided headers.

**Important:** The `mcp_headers` parameter is sent in the **JSON request body**, not as a query parameter.

```bash
curl -s -X POST http://localhost:8080/v1/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user-k8s-token-123" \
  -d '{
    "query": "What tools are available now?",
    "mcp_headers": {"mock-client-auth": {"Authorization": "Bearer my-client-token-456"}}
  }' | jq -r '.response'
```

**Check Terminal 1 (mock server logs):**

You should now see **THREE** requests:
1. From `mock-file-auth` with header: `Authorization: Bearer test-secret-token-123`
2. From `mock-k8s-auth` with header: `Authorization: Bearer user-k8s-token-123`
3. From `mock-client-auth` with header: `Authorization: Bearer my-client-token-456` ⭐

**Verify all captured headers:**
```bash
curl -s http://localhost:3000/debug/requests | jq
```

✅ **What this proves:** Client-provided headers are correctly parsed, resolved, and passed to MCP servers!

## Step 8: Test Streaming Query Without Client Headers

Now test the streaming endpoint **without** client headers:

```bash
curl -s -X POST http://localhost:8080/v1/streaming_query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user-k8s-token-123" \
  -d '{
    "query": "What tools are available?"
  }'
```

**Expected response:** Streaming response with only 2 tools (file-based and k8s-based).

**Check OLS logs (Terminal 2):**
You should see:
```
WARNING: MCP server mock-client-auth requires client headers but none provided
INFO: MCP servers provided: ['mock-file-auth', 'mock-k8s-auth']
```

**Verify mock server logs:**
```bash
curl -s http://localhost:3000/debug/requests | jq '.[-6:] | [.[] | {timestamp, auth: .headers.Authorization}]'
```

You should see requests with:
- `Bearer test-secret-token-123` (file-based)
- `Bearer user-k8s-token-123` (kubernetes)
- No client-auth requests

✅ **What this proves:** Streaming endpoint also gracefully skips servers without client headers.

## Step 9: Test Streaming Query WITH Client Headers

Test the streaming endpoint **with** client-provided headers:

```bash
curl -s -X POST http://localhost:8080/v1/streaming_query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user-k8s-token-123" \
  -d '{
    "query": "What tools are available now?",
    "mcp_headers": {"mock-client-auth": {"Authorization": "Bearer streaming-client-token-789"}}
  }'
```

**Expected response:** Streaming response with all 3 tools.

**Check OLS logs (Terminal 2):**
You should see:
```
INFO: MCP servers provided: ['mock-file-auth', 'mock-k8s-auth', 'mock-client-auth']
INFO: Loaded 1 tools from MCP server 'mock-file-auth'
INFO: Loaded 1 tools from MCP server 'mock-k8s-auth'
INFO: Loaded 1 tools from MCP server 'mock-client-auth'
```

**Verify all three headers were sent:**
```bash
curl -s http://localhost:3000/debug/requests | jq '.[-9:] | [.[] | {timestamp, auth: .headers.Authorization}]'
```

You should see requests with:
- `Bearer test-secret-token-123` (file-based) ✅
- `Bearer user-k8s-token-123` (kubernetes) ✅
- `Bearer streaming-client-token-789` (client-provided) ✅ ⭐

✅ **What this proves:** Streaming endpoint correctly accepts and uses client-provided headers!

## Step 10: Verify Header Resolution

Check the mock server debug endpoint:

```bash
curl -s http://localhost:3000/debug/headers | jq
```

You should see the last request's headers, including the client-provided Authorization.

## Expected Results Summary

| Test | mock-file-auth | mock-k8s-auth | mock-client-auth |
|------|----------------|---------------|------------------|
| Discovery endpoint | Not listed | Not listed | ✅ Listed (requires client headers) |
| Query without client headers | ✅ Contacted (file token) | ✅ Contacted (k8s token) | ❌ Skipped (missing headers) |
| Query WITH client headers | ✅ Contacted (file token) | ✅ Contacted (k8s token) | ✅ Contacted (client token) |
| **Streaming** query without headers | ✅ Contacted (file token) | ✅ Contacted (k8s token) | ❌ Skipped (missing headers) |
| **Streaming** query WITH headers | ✅ Contacted (file token) | ✅ Contacted (k8s token) | ✅ Contacted (client token) |

**Both `/v1/query` and `/v1/streaming_query` endpoints support the `mcp_headers` parameter!**

## Step 11: Test Tool Approval Flow

Use `test-olsconfig-pr3-approval.yaml` which enables `tools_approval` with `approval_type: tool_annotations` and a 2-second timeout.

Approval triggers on tools that do **not** have `readOnlyHint: true`. The mock server returns `mock_tool_client` with `readOnlyHint: false` only when the auth header contains `streaming-client-token`, so you must pass `mcp_headers` to load that tool.

### 11a: Trigger an approval-required tool call (expect timeout)

```bash
curl -s -N -X POST http://localhost:8080/v1/streaming_query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-token" \
  -d '{
    "query": "use the mock_tool_client tool to send message hello",
    "mcp_headers": {"mock-client-auth": {"Authorization": "Bearer streaming-client-token-789"}}
  }'
```

**Expected streaming output:**

1. `Tool call` — LLM requests `mock_tool_client`
2. `Approval request` — contains `approval_id`, `tool_annotation` with `readOnlyHint: false`
3. `Tool result` — status `error`, approval timed out after 2 seconds (nobody approved)

### 11b: Verify read-only tools skip approval

```bash
curl -s -N -X POST http://localhost:8080/v1/streaming_query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-token" \
  -d '{
    "query": "use the mock_tool_file tool to send message hello"
  }'
```

**Expected:** Tool executes immediately with status `success` — no approval event emitted because `mock_tool_file` has `readOnlyHint: true`.

### Why `mcp_headers` matters for approval testing

Tools loaded at startup (`mock_tool_file`, `mock_tool_no_auth`) all have `readOnlyHint: true` and bypass approval. The `mock_tool_client` tool (with `readOnlyHint: false`) only loads when `mcp_headers` provides the client-auth token at request time. Without `mcp_headers`, no tool in the system will trigger the approval flow.

## Troubleshooting

### Mock server not receiving requests
- Verify mock server is running in Terminal 1
- Check OLS logs in Terminal 2 for errors
- Ensure port 3000 is not blocked

### OLS fails to start
- Check config file path: `tests/mcp_mock/test-olsconfig.yaml`
- Verify `/tmp/fake-key` exists
- Check OLS logs for validation errors

### "Server not found" errors
- Verify MCP server names in config match curl commands
- Check mock server is listening on http://localhost:3000

### Client headers not working
- Verify `mcp_headers` is in the JSON request body, not a query parameter
- Check OLS logs for parsing errors
- Use `curl -v` to see request details
- Ensure the JSON string is properly escaped

## Cleanup

When done testing:

1. Stop OLS (Ctrl+C in Terminal 2)
2. Stop mock server (Ctrl+C in Terminal 1)
3. Optional: Clean up test files
   ```bash
   rm /tmp/mcp-test-token
   rm /tmp/test-openai-key
   # test-olsconfig.yaml can be kept for future testing
   ```

## Next Steps

After successful manual testing:
1. Document any issues found
2. Proceed with automated e2e tests (Step 3)
3. Test with real MCP servers if available

## Notes for E2E Test Implementation

Key scenarios to automate:
- ✅ Discovery endpoint returns correct servers
- ✅ Query without client headers (partial success)
- ✅ Query with client headers (full success)
- ✅ Invalid header format (graceful degradation)
- ✅ Missing required headers (server skipped)
- ✅ Multiple header dicts for single server
