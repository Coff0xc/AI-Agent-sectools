"""SSL/TLS security scanner."""
import ssl
import socket
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
from ..base import BaseTool
from ..models import ToolResult, ToolStatus
from ...safety.models import Target


# Weak cipher suites
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "ADH", "AECDH"
]

# Deprecated protocols
DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]


class SSLScanner(BaseTool):
    """SSL/TLS security scanner."""

    name = "ssl_scanner"
    description = "SSL/TLS certificate and configuration scanner"
    category = "web"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def execute(self, target: Target, params: Optional[Dict] = None) -> ToolResult:
        """Execute SSL/TLS scan."""
        params = params or {}
        check_ciphers = params.get("check_ciphers", True)

        # Extract host and port
        host, port = self._extract_host_port(target.value)

        # Run scan in thread pool (ssl is blocking)
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, self._scan_ssl, host, port, check_ciphers)

        # Parse results
        parsed = self._parse_results(host, port, results)

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            raw_output=str(results),
            parsed_data=parsed,
            execution_time=0.0
        )

    def _extract_host_port(self, target: str) -> tuple:
        """Extract host and port from target."""
        if target.startswith("https://"):
            target = target[8:]
        elif target.startswith("http://"):
            target = target[7:]

        target = target.split("/")[0]

        if ":" in target:
            host, port = target.rsplit(":", 1)
            return host, int(port)
        return target, 443

    def _scan_ssl(self, host: str, port: int, check_ciphers: bool) -> Dict[str, Any]:
        """Perform SSL/TLS scan."""
        results = {
            "host": host,
            "port": port,
            "certificate": None,
            "protocol": None,
            "cipher": None,
            "issues": []
        }

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert(binary_form=True)
                    cert_info = ssl.DER_cert_to_PEM_cert(cert)

                    # Get connection info
                    results["protocol"] = ssock.version()
                    results["cipher"] = ssock.cipher()

                    # Parse certificate
                    results["certificate"] = self._parse_certificate(ssock.getpeercert())

            # Check for deprecated protocols
            results["protocol_support"] = self._check_protocols(host, port)

        except ssl.SSLError as e:
            results["issues"].append({"type": "ssl_error", "message": str(e)})
        except socket.timeout:
            results["issues"].append({"type": "timeout", "message": "Connection timed out"})
        except Exception as e:
            results["issues"].append({"type": "error", "message": str(e)})

        return results

    def _parse_certificate(self, cert: Dict) -> Dict[str, Any]:
        """Parse certificate information."""
        if not cert:
            return {}

        # Parse dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        # Parse subject
        subject = {}
        for item in cert.get("subject", ()):
            for key, value in item:
                subject[key] = value

        # Parse issuer
        issuer = {}
        for item in cert.get("issuer", ()):
            for key, value in item:
                issuer[key] = value

        # Parse SANs
        sans = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            sans.append({"type": san_type, "value": san_value})

        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "serial_number": cert.get("serialNumber", ""),
            "version": cert.get("version", ""),
            "sans": sans
        }

    def _check_protocols(self, host: str, port: int) -> Dict[str, bool]:
        """Check which protocols are supported."""
        protocols = {}

        protocol_versions = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]

        for name, version in protocol_versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version

                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        protocols[name] = True
            except:
                protocols[name] = False

        return protocols

    def _parse_results(self, host: str, port: int, results: Dict) -> Dict[str, Any]:
        """Parse scan results into findings."""
        findings = []

        cert = results.get("certificate", {})
        protocol = results.get("protocol", "")
        cipher = results.get("cipher", ())
        protocol_support = results.get("protocol_support", {})

        # Check certificate expiry
        if cert.get("not_after"):
            try:
                expiry = datetime.strptime(cert["not_after"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now()).days

                if days_left < 0:
                    findings.append({
                        "type": "expired_certificate",
                        "severity": "high",
                        "description": f"SSL certificate expired {abs(days_left)} days ago"
                    })
                elif days_left < 30:
                    findings.append({
                        "type": "expiring_certificate",
                        "severity": "medium",
                        "description": f"SSL certificate expires in {days_left} days"
                    })
            except:
                pass

        # Check for self-signed certificate
        if cert.get("subject") == cert.get("issuer"):
            findings.append({
                "type": "self_signed_certificate",
                "severity": "medium",
                "description": "Self-signed SSL certificate detected"
            })

        # Check deprecated protocols
        for proto in ["TLSv1.0", "TLSv1.1"]:
            if protocol_support.get(proto):
                findings.append({
                    "type": "deprecated_protocol",
                    "severity": "medium",
                    "description": f"Deprecated protocol {proto} is supported"
                })

        # Check TLS 1.3 support
        if not protocol_support.get("TLSv1.3"):
            findings.append({
                "type": "missing_tls13",
                "severity": "low",
                "description": "TLS 1.3 is not supported"
            })

        # Check cipher strength
        if cipher and len(cipher) >= 2:
            cipher_name = cipher[0]
            for weak in WEAK_CIPHERS:
                if weak in cipher_name:
                    findings.append({
                        "type": "weak_cipher",
                        "severity": "high",
                        "description": f"Weak cipher suite in use: {cipher_name}"
                    })
                    break

        # Add issues from scan
        for issue in results.get("issues", []):
            findings.append({
                "type": issue["type"],
                "severity": "medium",
                "description": issue["message"]
            })

        return {
            "host": host,
            "port": port,
            "certificate": cert,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "protocol_support": protocol_support,
            "findings": findings,
            "summary": {
                "total_issues": len(findings),
                "high": len([f for f in findings if f["severity"] == "high"]),
                "medium": len([f for f in findings if f["severity"] == "medium"]),
                "low": len([f for f in findings if f["severity"] == "low"]),
            }
        }

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        return {"raw": raw_output}

    def validate_params(self, params: Dict) -> bool:
        return True
