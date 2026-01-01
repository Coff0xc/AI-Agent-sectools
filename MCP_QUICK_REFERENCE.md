# MCP Tools Quick Reference

## 8 Available Tools

### 1. 🔍 pentest_scan
Execute AI-driven penetration test scan
```
Parameters:
- target (required): Domain/IP/URL to scan
- scan_type (required): web | network | api
- llm_provider (optional): openai | anthropic | ollama
- max_iterations (optional): Number (default: 5)

Example: "Scan example.com for web vulnerabilities"
```

### 2. 📊 pentest_get_results
Get detailed scan results
```
Parameters:
- scan_id (required): UUID from pentest_scan

Example: "Get results for scan abc-123"
```

### 3. 📋 pentest_list_scans
List all scan history
```
Parameters:
- limit (optional): Number of results

Example: "List last 10 scans"
```

### 4. ⏱️ pentest_get_scan_status
Get current scan status
```
Parameters:
- scan_id (required): UUID from pentest_scan

Example: "Check status of scan abc-123"
```

### 5. ⚙️ pentest_configure_llm
Configure LLM provider
```
Parameters:
- provider (required): openai | anthropic | ollama
- model (optional): Model name
- api_key (optional): API key

Example: "Configure LLM to use Claude"
```

### 6. 🛠️ pentest_list_tools
List available penetration testing tools
```
Parameters:
- category (optional): Tool category filter

Example: "List all available tools"
```

### 7. 🎯 pentest_configure_scope
Configure scan scope (whitelist)
```
Parameters:
- allowed_domains (optional): Array of domains
- allowed_ips (optional): Array of IPs
- blacklist (optional): Array of patterns

Example: "Add testsite.com to allowed domains"
```

### 8. 📝 pentest_get_config
Get current configuration
```
Parameters: None

Example: "Show current configuration"
```

## Quick Start

1. **Configure MCP Client** (Claude Desktop example):
```json
{
  "mcpServers": {
    "ai-pentest": {
      "command": "python",
      "args": ["path/to/mcp_server.py"],
      "env": {
        "OPENAI_API_KEY": "your-key"
      }
    }
  }
}
```

2. **Add Target to Whitelist** (`mcp_auth_config.yaml`):
```yaml
authorization:
  whitelist:
    domains:
      - "your-target.com"
```

3. **Run Scan**:
```
User: Scan your-target.com for web vulnerabilities
```

## Authorization

- **Whitelist Mode** (default): Only pre-configured targets allowed
- **Audit Logging**: All operations logged to `logs/mcp_audit.log`
- **Blacklist**: Government/military domains always blocked

## Common Workflows

### Basic Scan
```
1. "Scan example.com for web vulnerabilities"
2. "Get results for that scan"
```

### Configure and Scan
```
1. "Configure LLM to use Claude"
2. "Scan example.com for web vulnerabilities"
```

### Review History
```
1. "List all scans"
2. "Get results for scan abc-123"
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| Target not authorized | Add to whitelist in `mcp_auth_config.yaml` |
| Invalid API key | Check `.env` file |
| Server won't start | Run `pip install -r requirements.txt` |

## Security Reminders

⚠️ **Only scan authorized targets**
⚠️ **Keep audit logs enabled**
⚠️ **Review whitelist regularly**
⚠️ **Secure your API keys**

---

For detailed documentation, see [MCP_USAGE.md](MCP_USAGE.md)
