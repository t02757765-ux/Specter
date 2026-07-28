import re
from typing import Dict, Any, List
from specter.signatures.db import SIGNATURE_DATABASE

class SignatureMatcher:
    def __init__(self):
        self.signatures = SIGNATURE_DATABASE

    def match(self, raw_socket_data: Dict[str, Any], http_data: Dict[str, Any]) -> List[Dict[str, str]]:
        detected_technologies = []

        # 1. Raw Socket Banner Fingerprinting
        service_hint = raw_socket_data.get("service_hint", "")
        extracted_ver = raw_socket_data.get("extracted_version")

        if service_hint not in ("unknown", "Generic Socket"):
            tech_info = {
                "name": service_hint,
                "category": "Network Service",
                "version": extracted_ver if extracted_ver else "Detected"
            }
            detected_technologies.append(tech_info)

        # Extract Server Header Info
        headers = http_data.get("headers", {})
        headers_str = "\n".join([f"{k.lower()}: {v.lower()}" for k, v in headers.items()])
        server_header = headers.get("Server") or headers.get("server")
        if server_header:
            detected_technologies.append({
                "name": "Web Server",
                "category": "Infrastructure",
                "version": str(server_header)
            })

        # Check PHP precise version from Header
        php_match = re.search(r"x-powered-by:.*php/([\d\.]+)", headers_str, re.IGNORECASE)
        if php_match:
            detected_technologies.append({
                "name": "PHP Runtime",
                "category": "Web Runtime",
                "version": php_match.group(1)
            })

        # 2. HTTP Deep Fingerprinting
        cookies = http_data.get("cookies", {})
        cookies_str = "\n".join([f"{k.lower()}={v.lower()}" for k, v in cookies.items()])
        dom_title = http_data.get("dom_title", "")
        favicon_hash = http_data.get("favicon_mmh3")
        endpoint_resps = http_data.get("endpoint_responses", {})

        for sig in self.signatures:
            is_match = False
            version_found = "Detected"

            # Header & Cookie Match
            for h_regex in sig.get("header_regex", []):
                if re.search(h_regex, headers_str, re.IGNORECASE) or re.search(h_regex, cookies_str, re.IGNORECASE):
                    is_match = True
                    break

            # DOM Regex Match
            if not is_match:
                for d_regex in sig.get("dom_regex", []):
                    if re.search(d_regex, dom_title, re.IGNORECASE):
                        is_match = True
                        break

            # Favicon MMH3 Match
            if not is_match and favicon_hash and favicon_hash in sig.get("favicon_mmh3", []):
                is_match = True

            # Endpoint Probe Response Match
            if not is_match and sig.get("endpoint_match"):
                ep_rule = sig["endpoint_match"]
                path = ep_rule["path"]
                if path in endpoint_resps:
                    res = endpoint_resps[path]
                    if res["status"] == ep_rule["status"] and ep_rule["contains"] in res["body_snippet"]:
                        is_match = True

            if is_match:
                if not any(t["name"] == sig["name"] for t in detected_technologies):
                    detected_technologies.append({
                        "name": sig["name"],
                        "category": sig["category"],
                        "version": version_found
                    })

        return detected_technologies
