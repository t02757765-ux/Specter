import asyncio
from typing import Dict, Any, List, Optional, Callable
from specter.scripts.modules.redis_info import RedisInfoScript
from specter.scripts.modules.mysql_auth import MySQLAuthScript
from specter.scripts.modules.smb_enum import SMBEnumScript
from specter.scripts.modules.ollama_models import OllamaModelsScript
from specter.scripts.modules.postgres_audit import PostgresAuditScript
from specter.scripts.modules.http_security_headers import HTTPSecurityHeadersScript

class ScriptEngine:
    def __init__(self, verbose_cb: Optional[Callable[[str], None]] = None):
        self.verbose_cb = verbose_cb
        self.scripts = [
            RedisInfoScript(),
            MySQLAuthScript(),
            SMBEnumScript(),
            OllamaModelsScript(),
            PostgresAuditScript(),
            HTTPSecurityHeadersScript()
        ]

    def _log(self, msg: str) -> None:
        if self.verbose_cb:
            self.verbose_cb(msg)

    async def run_scripts_for_target(self, ip: str, port_details: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        for detail in port_details:
            port = detail["port"]
            for script in self.scripts:
                if script.should_run(port, detail):
                    self.verbose_cb and self._log(f"[SCRIPT] Executing {script.name} on {ip}:{port}")
                    try:
                        script_res = await script.execute(ip, port, detail)
                        if script_res:
                            results.append({
                                "port": port,
                                "script_name": script.name,
                                "output": script_res
                            })
                    except Exception as e:
                        self._log(f"[SCRIPT ERROR] {script.name} failed on {ip}:{port}: {str(e)}")
        return results
