import asyncio
import aiohttp
import base64
import mmh3
from bs4 import BeautifulSoup
from typing import Dict, Any, List

class HTTPProbe:
    def __init__(self, timeout: float = 5.0, user_agent: str = "SpecterRecon/1.0.0"):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent

    async def analyze_url(self, base_url: str, endpoints: List[str]) -> Dict[str, Any]:
        combined_result = {
            "is_http": False,
            "status_code": 0,
            "headers": {},
            "cookies": {},
            "dom_title": "",
            "dom_meta": [],
            "scripts": [],
            "favicon_mmh3": None,
            "endpoint_responses": {}
        }

        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn, timeout=self.timeout) as session:
            # 1. Primary Base URL Fetch
            try:
                headers = {"User-Agent": self.user_agent}
                async with session.get(base_url, headers=headers, allow_redirects=True) as resp:
                    combined_result["is_http"] = True
                    combined_result["status_code"] = resp.status
                    combined_result["headers"] = dict(resp.headers)
                    combined_result["cookies"] = {k: v.value for k, v in resp.cookies.items()}
                    
                    text = await resp.text(errors="ignore")
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    if soup.title and soup.title.string:
                        combined_result["dom_title"] = soup.title.string.strip()
                    
                    for meta in soup.find_all('meta'):
                        name = meta.get('name') or meta.get('property')
                        content = meta.get('content')
                        if name and content:
                            combined_result["dom_meta"].append({"name": str(name), "content": str(content)})
                            
                    for script in soup.find_all('script'):
                        src = script.get('src')
                        if src:
                            combined_result["scripts"].append(str(src))
            except Exception:
                return combined_result

            # 2. Favicon Fetch and MurmurHash3 Generation
            favicon_url = f"{base_url.rstrip('/')}/favicon.ico"
            try:
                async with session.get(favicon_url, headers={"User-Agent": self.user_agent}) as fav_resp:
                    if fav_resp.status == 200:
                        fav_bytes = await fav_resp.read()
                        b64_data = base64.b64encode(fav_bytes)
                        chunked_b64 = []
                        for i in range(0, len(b64_data), 76):
                            chunked_b64.append(b64_data[i:i+76].decode('utf-8'))
                        formatted_b64 = "\n".join(chunked_b64) + "\n"
                        combined_result["favicon_mmh3"] = str(mmh3.hash(formatted_b64.encode('utf-8')))
            except Exception:
                pass

            # 3. Dynamic Endpoint Enumeration Probe
            for ep in endpoints:
                if ep in ["/", "/favicon.ico"]:
                    continue
                ep_url = f"{base_url.rstrip('/')}{ep}"
                try:
                    async with session.get(ep_url, headers={"User-Agent": self.user_agent}, allow_redirects=False) as ep_resp:
                        ep_text = await ep_resp.text(errors="ignore")
                        combined_result["endpoint_responses"][ep] = {
                            "status": ep_resp.status,
                            "headers": dict(ep_resp.headers),
                            "body_snippet": ep_text[:500]
                        }
                except Exception:
                    pass

        return combined_result
