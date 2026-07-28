import asyncio
import re
from typing import Dict, Any, Optional, Tuple

class RawSocketProbe:
    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    async def execute_probe(self, ip: str, port: int) -> Dict[str, Any]:
        result = {
            "port": port,
            "banner": "",
            "service_hint": "unknown",
            "extracted_version": None
        }

        payload = self._get_payload_for_port(port)
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )
            
            if payload:
                writer.write(payload)
                await writer.drain()

            data = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()

            raw_banner = data.decode('utf-8', errors='ignore')
            result["banner"] = raw_banner
            service_name, version_str = self._analyze_raw_banner(port, raw_banner, data)
            result["service_hint"] = service_name
            result["extracted_version"] = version_str

        except Exception:
            pass

        return result

    def _get_payload_for_port(self, port: int) -> bytes:
        if port in (80, 443, 8000, 8080, 8443):
            return b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Specter\r\n\r\n"
        elif port == 6379:
            return b"PING\r\n"
        elif port == 5432:
            # PostgreSQL Startup Packet Payload
            return b"\x00\x00\x00\x1d\x00\x03\x00\x00user\x00postgres\x00\x00"
        elif port == 27017:
            # MongoDB OP_QUERY payload
            return b"\x3d\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x13ismaster\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x00"
        elif port == 3389:
            # RDP TPKT / X.224 Connection Request
            return b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        return b""

    def _analyze_raw_banner(self, port: int, banner: str, raw_bytes: bytes) -> Tuple[str, Optional[str]]:
        # SSH Banner Analysis
        if "SSH-" in banner:
            match = re.search(r"SSH-([\d\.]+)-(\S+)", banner)
            if match:
                return "SSH", f"Protocol {match.group(1)} ({match.group(2)})"
            return "SSH", banner.strip()

        # FTP Banner Analysis
        if banner.startswith("220"):
            return "FTP", banner.strip()

        # SMTP Banner Analysis
        if banner.startswith("220 ") and ("SMTP" in banner or "Mail" in banner or "ESMTP" in banner):
            return "SMTP", banner.strip()

        # Redis Ping Response
        if "+PONG" in banner or "-ERR" in banner:
            return "Redis", "Redis Key-Value Store"

        # MySQL Handshake Header Parsing
        if len(raw_bytes) > 5 and not raw_bytes.startswith(b"HTTP"):
            if b"mysql_native_password" in raw_bytes or b"caching_sha2_password" in raw_bytes or port == 3306:
                version_match = re.search(r"([\d\.]+-[\w\.-]+)", banner)
                if version_match:
                    return "MySQL", version_match.group(1)
                return "MySQL", "Database Engine"

        # PostgreSQL Header Error/Auth Response
        if port == 5432 or raw_bytes.startswith(b"R") or raw_bytes.startswith(b"E"):
            if "FATAL" in banner or "postgres" in banner.lower():
                return "PostgreSQL", "Database Engine"

        return "Generic Socket", None
