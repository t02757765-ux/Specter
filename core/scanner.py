import asyncio
import socket
from typing import List
from specter.core.rate_limiter import RateLimiter

class PortScanner:
    def __init__(self, concurrency: int, timeout: float, rate_limiter: RateLimiter, retries: int = 2):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.rate_limiter = rate_limiter
        self.retries = retries

    async def check_port(self, ip: str, port: int) -> bool:
        for attempt in range(self.retries + 1):
            await self.rate_limiter.acquire()
            async with self.semaphore:
                try:
                    conn = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                    writer.close()
                    await writer.wait_closed()
                    return True
                except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                    if attempt < self.retries:
                        await asyncio.sleep(0.1 * (attempt + 1))
                        continue
                    return False
                except Exception:
                    return False
        return False

    async def scan_target(self, ip: str, ports: List[int]) -> List[int]:
        tasks = [self.check_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports = []
        for port, is_open in zip(ports, results):
            if isinstance(is_open, bool) and is_open:
                open_ports.append(port)
        return open_ports
