"""Authorization management for MCP server."""
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


class AuthorizationManager:
    """Manages authorization for MCP tool calls."""

    def __init__(self, config_path: str = "mcp_auth_config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.logger = logging.getLogger(__name__)

    def _load_config(self) -> Dict[str, Any]:
        """Load authorization configuration."""
        if not self.config_path.exists():
            return self._default_config()

        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _default_config(self) -> Dict[str, Any]:
        """Return default authorization configuration."""
        return {
            "authorization": {
                "mode": "whitelist",
                "whitelist": {
                    "domains": ["*.example.com", "testsite.local", "httpbin.org"],
                    "ip_ranges": ["192.168.0.0/16", "10.0.0.0/8"]
                },
                "blacklist": ["*.gov", "*.mil", "*.edu"],
                "audit": {
                    "enabled": True,
                    "log_file": "logs/mcp_audit.log"
                }
            }
        }

    def is_authorized(self, target: str) -> bool:
        """Check if target is authorized for scanning."""
        auth_config = self.config.get("authorization", {})

        # Check blacklist first
        if self._is_blacklisted(target, auth_config.get("blacklist", [])):
            self.logger.warning(f"Target {target} is blacklisted")
            return False

        # Check whitelist
        mode = auth_config.get("mode", "whitelist")
        if mode == "whitelist":
            whitelist = auth_config.get("whitelist", {})
            if self._is_whitelisted(target, whitelist):
                return True
            self.logger.warning(f"Target {target} not in whitelist")
            return False

        return True

    def _is_blacklisted(self, target: str, blacklist: List[str]) -> bool:
        """Check if target matches blacklist patterns."""
        for pattern in blacklist:
            if self._matches_pattern(target, pattern):
                return True
        return False

    def _is_whitelisted(self, target: str, whitelist: Dict[str, List[str]]) -> bool:
        """Check if target matches whitelist patterns."""
        domains = whitelist.get("domains", [])
        for pattern in domains:
            if self._matches_pattern(target, pattern):
                return True
        return False

    def _matches_pattern(self, target: str, pattern: str) -> bool:
        """Check if target matches a pattern (supports wildcards)."""
        import re
        pattern_regex = pattern.replace(".", r"\.").replace("*", ".*")
        return bool(re.match(f"^{pattern_regex}$", target))

    def log_audit(self, tool_name: str, target: str, result: str):
        """Log audit entry."""
        audit_config = self.config.get("authorization", {}).get("audit", {})
        if not audit_config.get("enabled", True):
            return

        log_file = Path(audit_config.get("log_file", "logs/mcp_audit.log"))
        log_file.parent.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().isoformat()
        entry = f"{timestamp} | {tool_name} | {target} | {result}\n"

        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(entry)
