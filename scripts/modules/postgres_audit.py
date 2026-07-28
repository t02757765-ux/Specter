import asyncio
from typing import Dict, Any, Optional

class PostgresAuditScript:
    name = "postgres-auth-check"

    def should_run(self, port: int, detail: Dict[str, Any]) -> bool:
        return port == 5432 or detail.get("raw_socket", {}).get("service_hint") == "PostgreSQL"

    async def execute(self, ip: str, port: int, detail: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3.0)
            writer.write(b"\x00\x00\x00\x1d\x00\x03\x00\x00user\x00postgres\x00\x00")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            writer.close()
            await writer.wait_closed()

            if data.startswith(b"R") or data.startswith(b"E"):
                return {
                    "vulnerable": False,
                    "issue": "PostgreSQL Service Responding",
                    "details": "Server returned standard Auth/Error response packet."
                }
        except Exception:
            pass
        return None
