import os
import yaml
from typing import Dict, Any, List

class Config:
    def __init__(self, config_dict: Dict[str, Any]):
        self.timeout: float = float(config_dict.get("global", {}).get("timeout", 4.0))
        self.max_concurrency: int = int(config_dict.get("global", {}).get("max_concurrency", 500))
        self.rate_limit: int = int(config_dict.get("global", {}).get("rate_limit", 1000))
        self.retries: int = int(config_dict.get("global", {}).get("retries", 2))
        self.user_agent: str = str(config_dict.get("global", {}).get("user_agent", "SpecterRecon/1.0.0"))
        
        scanner_ports = config_dict.get("scanner", {}).get("ports", "80,443")
        self.default_ports: List[int] = self._parse_ports(str(scanner_ports))
        self.http_endpoints: List[str] = config_dict.get("probes", {}).get("http_endpoints", ["/"])

    @staticmethod
    def _parse_ports(port_str: str) -> List[int]:
        ports = set()
        for part in port_str.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    ports.update(range(start, end + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    continue
        return sorted(list(ports))

    @classmethod
    def load_from_file(cls, path: str) -> "Config":
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                return cls(data)
            except Exception:
                return cls({})
        return cls({})
