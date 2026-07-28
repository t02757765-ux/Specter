import asyncio
import hashlib
from typing import Optional, Callable

class JARMProbe:
    def __init__(self, timeout: float = 3.0, verbose_cb: Optional[Callable[[str], None]] = None):
        self.timeout = timeout
        self.verbose_cb = verbose_cb

    def _log(self, msg: str) -> None:
        if self.verbose_cb:
            self.verbose_cb(msg)

    async def scan_jarm(self, ip: str, port: int) -> Optional[str]:
        if port not in (443, 8443, 9443, 465, 993, 995):
            return None
            
        self._log(f"[JARM] Initiating Salesforce JARM TLS probes against {ip}:{port}")
        
        jarm_probes = [
            b"\x16\x03\x01\x00\x2a\x01\x00\x00\x26\x03\x03" + b"\x00" * 32 + b"\x00\x02\x00\x2f\x01\x00",
            b"\x16\x03\x01\x00\x2a\x01\x00\x00\x26\x03\x01" + b"\x00" * 32 + b"\x00\x02\x00\x35\x01\x00",
            b"\x16\x03\x03\x00\x2a\x01\x00\x00\x26\x03\x03" + b"\x00" * 32 + b"\x00\x02\xc0\x2b\x01\x00",
            b"\x16\x03\x03\x00\x2a\x01\x00\x00\x26\x03\x03" + b"\x00" * 32 + b"\x00\x02\x13\x01\x01\x00",
            b"\x16\x03\x01\x00\x2a\x01\x00\x00\x26\x03\x02" + b"\x00" * 32 + b"\x00\x02\xc0\x13\x01\x00",
            b"\x16\x03\x03\x00\x2a\x01\x00\x00\x26\x03\x03" + b"\x00" * 32 + b"\x00\x02\x00\x0a\x01\x00",
            b"\x16\x03\x02\x00\x2a\x01\x00\x00\x26\x03\x02" + b"\x00" * 32 + b"\x00\x02\x00\x9c\x01\x00",
            b"\x16\x03\x03\x00\x2a\x01\x00\x00\x26\x03\x03" + b"\x00" * 32 + b"\x00\x02\xc0\x0a\x01\x00",
            b"\x16\x03\x01\x00\x2a\x01\x00\x00\x26\x03\x03" + b"\x00" * 32 + b"\x00\x02\x00\x61\x01\x00",
            b"\x16\x03\x03\x00\x2a\x01\x00\x00\x26\x03\x03" + b"\x00" * 32 + b"\x00\x02\xc0\x30\x01\x00"
        ]

        responses = []
        for probe in jarm_probes:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=self.timeout)
                writer.write(probe)
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                if len(resp) > 5 and resp[0] == 0x16:
                    cipher = resp[43:45].hex() if len(resp) >= 45 else "0000"
                    responses.append(cipher)
                else:
                    responses.append("0000")
            except Exception:
                responses.append("0000")

        combined = "".join(responses)
        if combined == "0000" * 10:
            return None

        cipher_part = combined[:30]
        ext_part = hashlib.sha256(combined.encode()).hexdigest()[:32]
        jarm_fingerprint = f"{cipher_part}{ext_part}"
        self._log(f"[JARM] Successfully computed JARM Fingerprint: {jarm_fingerprint}")
        return jarm_fingerprint
