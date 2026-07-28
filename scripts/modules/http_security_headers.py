from typing import Dict, Any, Optional

class HTTPSecurityHeadersScript:
    name = "http-security-headers-audit"

    def should_run(self, port: int, detail: Dict[str, Any]) -> bool:
        return detail.get("http_data", {}).get("is_http", False)

    async def execute(self, ip: str, port: int, detail: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = detail.get("http_data", {}).get("headers", {})
        missing = []

        if not any(k.lower() == "strict-transport-security" for k in headers):
            missing.append("HSTS")
        if not any(k.lower() == "content-security-policy" for k in headers):
            missing.append("CSP")
        if not any(k.lower() == "x-frame-options" for k in headers):
            missing.append("X-Frame-Options")

        cors = headers.get("Access-Control-Allow-Origin") or headers.get("access-control-allow-origin")

        if missing or cors == "*":
            return {
                "vulnerable": True if cors == "*" else False,
                "issue": "HTTP Security Header Misconfigurations",
                "details": f"Missing Headers: {', '.join(missing)} | CORS Wildcard: {cors == '*'}"
            }
        return None
