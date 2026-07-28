import asyncio
import re
import struct
from typing import Dict, Any, Optional, Tuple, Callable

class RawSocketProbe:
    def __init__(self, timeout: float = 4.0, verbose_cb: Optional[Callable[[str], None]] = None):
        self.timeout = timeout
        self.verbose_cb = verbose_cb

    def _log(self, msg: str) -> None:
        if self.verbose_cb:
            self.verbose_cb(msg)

    async def execute_probe(self, ip: str, port: int) -> Dict[str, Any]:
        result = {
            "port": port,
            "banner": "",
            "service_hint": "unknown",
            "extracted_version": None,
            "raw_hex": "",
            "os_hint": "Unknown"
        }

        payload = self._get_payload_for_port(port)
        
        try:
            self._log(f"[DEBUG] Opening raw binary socket to {ip}:{port}")
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
            result["raw_hex"] = data.hex()

            service_name, version_str = self._analyze_raw_banner(port, raw_banner, data)
            result["service_hint"] = service_name
            result["extracted_version"] = version_str

        except Exception as e:
            self._log(f"[DEBUG] Raw socket probe timeout/error on port {port}: {str(e)}")

        return result

    def _get_payload_for_port(self, port: int) -> bytes:
        if port in (80, 443, 8000, 8080, 8443):
            return b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Specter\r\n\r\n"
        elif port == 6379:
            return b"INFO\r\n"
        elif port == 11211:
            return b"stats\r\n"
        elif port == 1883:
            return b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00"
        elif port == 53:
            return b"\x00\x1e\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"
        elif port in (139, 445):
            return (
                b"\x00\x00\x00\x85\xfeSMB\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x02\x00\x01\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x00"
                b"\x00\x00\x00\x00\x02\x02\x10\x02"
            )
        elif port == 5432:
            return b"\x00\x00\x00\x1d\x00\x03\x00\x00user\x00postgres\x00\x00"
        elif port == 27017:
            return b"\x3d\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x13ismaster\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x00"
        elif port == 3389:
            return b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        return b""

    def _analyze_raw_banner(self, port: int, banner: str, raw_bytes: bytes) -> Tuple[str, Optional[str]]:
        if port == 3306 or (len(raw_bytes) > 5 and raw_bytes[4:5] == b"\x0a"):
            try:
                if len(raw_bytes) > 10 and raw_bytes[4] == 0x0a:
                    null_idx = raw_bytes.find(b"\x00", 5)
                    if null_idx != -1:
                        server_version = raw_bytes[5:null_idx].decode('utf-8', errors='ignore')
                        thread_id = struct.unpack("<I", raw_bytes[null_idx+1:null_idx+5])[0]
                        auth_plugin = "mysql_native_password" if b"mysql_native_password" in raw_bytes else "caching_sha2_password"
                        return "MySQL", f"Version: {server_version} (Thread ID: {thread_id}, Auth: {auth_plugin})"
            except Exception:
                pass

        if raw_bytes.startswith(b"\x00\x00") and b"\xfeSMB" in raw_bytes:
            dialect_str = "SMB 2.x / 3.x Engine"
            if b"\x02\x02" in raw_bytes:
                dialect_str = "SMB v2.0.2 Dialect"
            elif b"\x10\x02" in raw_bytes:
                dialect_str = "SMB v2.1 Dialect"
            elif b"\x00\x03" in raw_bytes:
                dialect_str = "SMB v3.0 Dialect"
            return "SMB", dialect_str

        if "# Server" in banner or "redis_version:" in banner:
            match = re.search(r"redis_version:([\d\.]+)", banner)
            ver = match.group(1) if match else "Active"
            return "Redis", f"Redis Server v{ver}"

        if "STAT pid" in banner or "STAT version" in banner:
            match = re.search(r"STAT version ([\d\.]+)", banner)
            ver = match.group(1) if match else "Active"
            return "Memcached", f"Memcached In-Memory Store v{ver}"

        if raw_bytes.startswith(b"\x20\x02"):
            return "MQTT", "MQTT Message Broker Active"

        if "SSH-" in banner:
            match = re.search(r"SSH-([\d\.]+)-(\S+)", banner)
            if match:
                return "SSH", f"Protocol {match.group(1)} ({match.group(2)})"
            return "SSH", banner.strip()

        if banner.startswith("220"):
            return "FTP", banner.strip()

        if banner.startswith("220 ") and ("SMTP" in banner or "Mail" in banner or "ESMTP" in banner):
            return "SMTP", banner.strip()

        if port == 5432 or raw_bytes.startswith(b"R") or raw_bytes.startswith(b"E"):
            if "FATAL" in banner or "postgres" in banner.lower():
                return "PostgreSQL", "Database Engine Active"

        return "Generic Socket", None
