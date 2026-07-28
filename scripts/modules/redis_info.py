import asyncio
from typing import Dict, Any, Optional

class RedisInfoScript:
    name = "redis-unauth-check"

    def should_run(self, port: int, detail: Dict[str, Any]) -> bool:
        return port == 6379 or "Redis" in detail.get("raw_socket", {}).get("service_hint", "")

    async def execute(self, ip: str, port: int, detail: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3.0)
            writer.write(b"INFO Server\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            writer.close()
            await writer.wait_closed()

            res_str = data.decode('utf-8', errors='ignore')
            if "redis_version" in res_str:
                return {
                    "vulnerable": True,
                    "issue": "Unauthenticated Redis Access Allowed",
                    "details": "Server answered 'INFO Server' without password authentication."
                }
        except Exception:
            pass
        return None
