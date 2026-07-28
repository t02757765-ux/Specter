import aiohttp
from typing import Dict, Any, Optional

class OllamaModelsScript:
    name = "ollama-model-enum"

    def should_run(self, port: int, detail: Dict[str, Any]) -> bool:
        return port == 11434 or any(t["name"] == "Ollama AI Engine" for t in detail.get("technologies", []))

    async def execute(self, ip: str, port: int, detail: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = f"http://{ip}:{port}/api/tags"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=3.0) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        models = [m.get("name") for m in data.get("models", [])]
                        return {
                            "vulnerable": True,
                            "issue": "Unauthenticated Ollama AI API Access",
                            "hosted_models": models
                        }
        except Exception:
            pass
        return None
