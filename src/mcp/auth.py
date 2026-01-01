"""Authorization management for MCP server."""
import yaml
import re
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


class AuthManager:
    """Manages authorization for MCP tool calls."""

    def __init__(self, config_path: str = "mcp_auth_config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.logger = logging.getLogger(__name__)

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return self._default_config()
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _default_config(self) -> Dict[str, Any]:
        return {
            "authorization": {
                "mode": "whitelist",
                "whitelist": {
                    "domains": ["*.example.com", "testsite.local", "httpbin.org"],
                    "ip_ranges": ["192.168.0.0/16", "10.0.0.0/8"]
                },
                "blacklist": ["*.gov", "*.mil", "*.edu"],
                "audit": {"enabled": True, "log_file": "logs/mcp_audit.log"}
            }
        }

    def is_authorized(self, target: str) -> bool:
        """Check if target is authorized."""
        auth = self.config.get("authorization", {})

        # Blacklist check
        for pattern in auth.get("blacklist", []):
            if self._match(target, pattern):
                self.logger.warning(f"Blacklisted: {target}")
                return False

        # Whitelist check
        if auth.get("mode") == "whitelist":
            for pattern in auth.get("whitelist", {}).get("domains", []):
                if self._match(target, pattern):
                    return True
            self.logger.warning(f"Not whitelisted: {target}")
            return False

        return True

    def _match(self, target: str, pattern: str) -> bool:
        regex = pattern.replace(".", r"\.").replace("*", ".*")
        return bool(re.match(f"^{regex}$", target))

    def log_audit(self, tool: str, target: str, result: str):
        """Log audit entry."""
        audit = self.config.get("authorization", {}).get("audit", {})
        if not audit.get("enabled", True):
            return

        log_file = Path(audit.get("log_file", "logs/mcp_audit.log"))
        log_file.parent.mkdir(parents=True, exist_ok=True)

        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now().isoformat()} | {tool} | {target} | {result}\n")

    def add_whitelist(self, domain: str):
        """Add domain to whitelist."""
        wl = self.config.setdefault("authorization", {}).setdefault("whitelist", {}).setdefault("domains", [])
        if domain not in wl:
            wl.append(domain)
