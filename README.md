# MCP Security Scanner

Pure MCP-based security scanning toolkit. No external tools required - all scanners are implemented in pure Python.

## ⚠️ Legal Disclaimer

**This tool is for authorized penetration testing only.** Users must:
- Obtain explicit written authorization before testing any target
- Comply with all applicable laws and regulations
- Accept full responsibility for their actions

## Features

- **Pure Python** - No external tools (nmap, nikto, etc.) required
- **MCP Protocol** - Works with Claude Code, Cursor, and other MCP clients
- **7 Security Tools**:
  - `scan_ports` - TCP port scanning with banner grabbing
  - `scan_web` - Directory and file enumeration
  - `scan_subdomains` - DNS subdomain enumeration
  - `scan_ssl` - SSL/TLS certificate analysis
  - `scan_vulns` - Web vulnerability detection (SQLi, XSS, LFI, SSRF)
  - `full_scan` - Complete reconnaissance
  - `add_target` - Whitelist management

## Quick Start

### 1. Install

```bash
git clone https://github.com/Coff0xc/AI-Agent-sectools.git
cd AI-Agent-sectools
pip install -r requirements.txt
```

### 2. Configure MCP Client

Add to your MCP client config (e.g., Claude Code):

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "python",
      "args": ["mcp_server.py"],
      "cwd": "/path/to/AI-Agent-sectools"
    }
  }
}
```

### 3. Use

In Claude Code or other MCP client:

```
# Add target to whitelist first
add_target example.com

# Then scan
scan_ports example.com
scan_web https://example.com
scan_subdomains example.com
scan_ssl example.com
scan_vulns https://example.com

# Or run full reconnaissance
full_scan example.com
```

## Project Structure

```
├── mcp_server.py          # Entry point
├── mcp_auth_config.yaml   # Authorization config
├── requirements.txt       # Dependencies
└── src/
    ├── mcp/
    │   ├── server.py      # MCP server
    │   └── auth.py        # Authorization
    └── scanner/
        ├── port.py        # Port scanner
        ├── web.py         # Web scanner
        ├── dns.py         # Subdomain scanner
        ├── ssl.py         # SSL scanner
        └── vuln.py        # Vulnerability scanner
```

## Authorization

Edit `mcp_auth_config.yaml` to configure allowed targets:

```yaml
authorization:
  mode: whitelist
  whitelist:
    domains:
      - "*.example.com"
      - "testsite.local"
  blacklist:
    - "*.gov"
    - "*.mil"
```

## License

MIT License - see LICENSE file.

---

**Remember:** Always obtain proper authorization before testing any system.
