import asyncio
from typing import Dict, Any, Optional

class MySQLAuthScript:
    name = "mysql-handshake-audit"

    def should_run(self, port: int, detail: Dict[str, Any]) -> bool:
        return port == 3306 or detail.get("raw_socket", {}).get("service_hint") == "MySQL"

    async def execute(self, ip: str, port: int, detail: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        extracted = detail.get("raw_socket", {}).get("extracted_version")
        if extracted:
            return {
                "vulnerable": False,
                "issue": "MySQL Protocol Info Disclosed",
                "details": f"Disclosed parameters: {extracted}"
            }
        return None
