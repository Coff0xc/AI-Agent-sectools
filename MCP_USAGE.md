# MCP Server Usage Guide

## Overview

The AI Penetration Testing MCP Server exposes the AI-powered penetration testing tool through the Model Context Protocol (MCP), allowing it to be called by MCP clients like Claude Code, iFlow CLI, Codex, and Gemini CLI.

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy the example environment file and configure your API keys:

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
OPENAI_API_KEY=sk-your-openai-key
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key
DEFAULT_LLM_PROVIDER=openai
DEFAULT_LLM_MODEL=gpt-3.5-turbo
MAX_ITERATIONS=5
```

### 3. Configure Authorization

Edit `mcp_auth_config.yaml` to configure which targets are authorized for scanning:

```yaml
authorization:
  mode: whitelist
  whitelist:
    domains:
      - "*.example.com"
      - "your-test-domain.com"
    ip_ranges:
      - "192.168.0.0/16"
  blacklist:
    - "*.gov"
    - "*.mil"
```

**Important:** Only add targets you have explicit authorization to test!

## MCP Client Configuration

### Claude Desktop

Add to your Claude Desktop configuration file:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ai-pentest": {
      "command": "python",
      "args": ["E:/workplace/[Github项目]自动化渗透/mcp_server.py"],
      "env": {
        "OPENAI_API_KEY": "your-key",
        "ANTHROPIC_API_KEY": "your-key"
      }
    }
  }
}
```

### Other MCP Clients

For other MCP clients (iFlow CLI, Codex, Gemini CLI), refer to their documentation for adding MCP servers. The general pattern is:

```bash
# Command to start the server
python /path/to/mcp_server.py
```

## Available Tools

The MCP server provides 8 tools:

### 1. pentest_scan

Execute an AI-driven penetration test scan.

**Parameters:**
- `target` (required): Target to scan (domain/IP/URL)
- `scan_type` (required): Type of scan (`web`, `network`, `api`)
- `llm_provider` (optional): LLM provider (`openai`, `anthropic`, `ollama`)
- `max_iterations` (optional): Maximum iterations

**Example:**
```
Scan example.com for web vulnerabilities
```

**Response:**
```json
{
  "success": true,
  "scan_id": "uuid-here",
  "target": "example.com",
  "scan_type": "web",
  "state": "completed",
  "findings_count": 5,
  "summary": "Scan completed with 5 findings"
}
```

### 2. pentest_get_results

Get detailed results from a completed scan.

**Parameters:**
- `scan_id` (required): Scan ID from pentest_scan

**Example:**
```
Get results for scan uuid-here
```

**Response:**
```json
{
  "success": true,
  "scan_id": "uuid-here",
  "findings": [
    {
      "type": "missing_security_header",
      "severity": "medium",
      "description": "Missing X-Frame-Options header",
      "location": "https://example.com"
    }
  ],
  "risk_score": 25,
  "recommendations": ["Add security headers"]
}
```

### 3. pentest_list_scans

List all scan history.

**Parameters:**
- `limit` (optional): Limit number of results

**Example:**
```
List all scans
```

### 4. pentest_get_scan_status

Get current status of a running scan.

**Parameters:**
- `scan_id` (required): Scan ID

**Example:**
```
Get status of scan uuid-here
```

### 5. pentest_configure_llm

Configure the LLM provider.

**Parameters:**
- `provider` (required): Provider name (`openai`, `anthropic`, `ollama`)
- `model` (optional): Model name
- `api_key` (optional): API key

**Example:**
```
Configure LLM to use Claude
```

### 6. pentest_list_tools

List available penetration testing tools.

**Parameters:**
- `category` (optional): Filter by category

**Example:**
```
List all available tools
```

### 7. pentest_configure_scope

Configure scan scope (add to whitelist).

**Parameters:**
- `allowed_domains` (optional): List of allowed domains
- `allowed_ips` (optional): List of allowed IPs

**Example:**
```
Add testsite.com to allowed domains
```

### 8. pentest_get_config

Get current configuration.

**Example:**
```
Show current configuration
```

## Usage Examples

### Example 1: Basic Web Scan

```
User: Use ai-pentest to scan httpbin.org for web vulnerabilities

Claude: I'll scan httpbin.org for web vulnerabilities.
[Calls pentest_scan with target="httpbin.org", scan_type="web"]

Result: Scan completed with 3 findings:
- Missing security headers (medium)
- Information disclosure (low)
- CORS misconfiguration (low)
```

### Example 2: Get Detailed Results

```
User: Get the detailed results for that scan

Claude: I'll retrieve the detailed results.
[Calls pentest_get_results with scan_id from previous scan]

Result: [Detailed findings with descriptions and recommendations]
```

### Example 3: Configure and Scan

```
User: Configure the tool to use Claude, then scan example.com

Claude: I'll configure the LLM provider and run the scan.
[Calls pentest_configure_llm with provider="anthropic"]
[Calls pentest_scan with target="example.com", scan_type="web"]
```

## Authorization and Security

### Whitelist Mode (Recommended)

In whitelist mode, only targets explicitly listed in `mcp_auth_config.yaml` can be scanned.

**To add a target:**

1. Edit `mcp_auth_config.yaml`
2. Add the domain or IP to the whitelist
3. Restart the MCP server (or use `pentest_configure_scope`)

### Audit Logging

All scan operations are logged to `logs/mcp_audit.log`:

```
2024-01-01T12:00:00 | pentest_scan | example.com | success
2024-01-01T12:05:00 | pentest_scan | unauthorized.com | unauthorized
```

### Security Best Practices

1. **Only scan authorized targets** - Ensure you have written permission
2. **Use whitelist mode** - Don't disable authorization
3. **Review audit logs** - Regularly check for unauthorized attempts
4. **Secure API keys** - Don't commit `.env` to version control
5. **Limit scope** - Only add necessary targets to whitelist

## Troubleshooting

### Server Won't Start

**Error:** `ModuleNotFoundError: No module named 'mcp'`

**Solution:** Install dependencies:
```bash
pip install -r requirements.txt
```

### Authorization Errors

**Error:** `Target example.com is not authorized`

**Solution:** Add the target to whitelist in `mcp_auth_config.yaml`:
```yaml
whitelist:
  domains:
    - "example.com"
```

### LLM API Errors

**Error:** `Invalid API key`

**Solution:** Check your `.env` file and ensure API keys are correct:
```env
OPENAI_API_KEY=sk-your-actual-key
```

### Scan Timeout

**Error:** `Scan timed out`

**Solution:** Increase timeout in `mcp_auth_config.yaml`:
```yaml
security:
  scan_timeout: 7200  # 2 hours
```

## Logs

- **Server logs:** `logs/mcp_server.log`
- **Audit logs:** `logs/mcp_audit.log`

## Legal Notice

**⚠️ IMPORTANT: This tool is for authorized penetration testing only.**

- Only scan systems you own or have explicit written permission to test
- Unauthorized scanning may be illegal in your jurisdiction
- The developers are not responsible for misuse of this tool
- Always comply with applicable laws and regulations

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review logs in `logs/` directory
3. Check the main README.md for architecture details
