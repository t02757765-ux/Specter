import asyncio
from typing import Dict, Any, Optional

class SMBEnumScript:
    name = "smb-version-check"

    def should_run(self, port: int, detail: Dict[str, Any]) -> bool:
        return port in (139, 445) or detail.get("raw_socket", {}).get("service_hint") == "SMB"

    async def execute(self, ip: str, port: int, detail: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raw_hex = detail.get("raw_socket", {}).get("raw_hex", "")
        if "fe534d42" in raw_hex:  # \xfeSMB header hex
            return {
                "vulnerable": False,
                "issue": "SMB2 Protocol Enabled",
                "details": "Server responds to SMB2 Negotiate Protocol requests."
            }
        return None
