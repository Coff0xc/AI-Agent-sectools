"""SSL/TLS security scanner."""
import ssl
import socket
from datetime import datetime
from typing import Dict, Any

WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]


class SSLScanner:
    """SSL/TLS certificate and configuration scanner."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def scan(self, target: str) -> Dict[str, Any]:
        """Scan SSL/TLS configuration."""
        host, port = self._parse_target(target)

        result = {
            "host": host, "port": port,
            "certificate": None, "protocol": None, "cipher": None,
            "findings": [], "protocol_support": {}
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    result["protocol"] = ssock.version()
                    result["cipher"] = ssock.cipher()
                    result["certificate"] = self._parse_cert(ssock.getpeercert())

            result["protocol_support"] = self._check_protocols(host, port)
            result["findings"] = self._analyze(result)

        except Exception as e:
            result["findings"].append({"type": "error", "severity": "medium", "description": str(e)})

        return result

    def _parse_target(self, target: str) -> tuple:
        if target.startswith("https://"):
            target = target[8:]
        elif target.startswith("http://"):
            target = target[7:]
        target = target.split("/")[0]

        if ":" in target:
            h, p = target.rsplit(":", 1)
            return h, int(p)
        return target, 443

    def _parse_cert(self, cert: Dict) -> Dict:
        if not cert:
            return {}

        subject = {k: v for item in cert.get("subject", ()) for k, v in item}
        issuer = {k: v for item in cert.get("issuer", ()) for k, v in item}

        return {
            "subject": subject, "issuer": issuer,
            "not_before": cert.get("notBefore", ""),
            "not_after": cert.get("notAfter", ""),
            "serial": cert.get("serialNumber", ""),
            "sans": [v for t, v in cert.get("subjectAltName", ())]
        }

    def _check_protocols(self, host: str, port: int) -> Dict[str, bool]:
        protocols = {}
        versions = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]

        for name, ver in versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver
                ctx.maximum_version = ver

                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        protocols[name] = True
            except:
                protocols[name] = False

        return protocols

    def _analyze(self, result: Dict) -> list:
        findings = []
        cert = result.get("certificate", {})
        proto_support = result.get("protocol_support", {})
        cipher = result.get("cipher", ())

        # Check expiry
        if cert.get("not_after"):
            try:
                exp = datetime.strptime(cert["not_after"], "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.now()).days
                if days < 0:
                    findings.append({"type": "expired_cert", "severity": "high",
                                     "description": f"Certificate expired {abs(days)} days ago"})
                elif days < 30:
                    findings.append({"type": "expiring_cert", "severity": "medium",
                                     "description": f"Certificate expires in {days} days"})
            except:
                pass

        # Self-signed
        if cert.get("subject") == cert.get("issuer"):
            findings.append({"type": "self_signed", "severity": "medium",
                             "description": "Self-signed certificate"})

        # Deprecated protocols
        for proto in ["TLSv1.0", "TLSv1.1"]:
            if proto_support.get(proto):
                findings.append({"type": "deprecated_protocol", "severity": "medium",
                                 "description": f"Deprecated {proto} supported"})

        # Missing TLS 1.3
        if not proto_support.get("TLSv1.3"):
            findings.append({"type": "no_tls13", "severity": "low",
                             "description": "TLS 1.3 not supported"})

        # Weak cipher
        if cipher and len(cipher) >= 1:
            for weak in WEAK_CIPHERS:
                if weak in cipher[0]:
                    findings.append({"type": "weak_cipher", "severity": "high",
                                     "description": f"Weak cipher: {cipher[0]}"})
                    break

        return findings
