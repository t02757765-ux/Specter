import ipaddress
import socket
from typing import List

class TargetResolver:
    @staticmethod
    def resolve_target(target_input: str) -> List[str]:
        target_input = target_input.strip()
        
        try:
            ip = ipaddress.ip_address(target_input)
            return [str(ip)]
        except ValueError:
            pass

        try:
            net = ipaddress.ip_network(target_input, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            pass

        if "-" in target_input and not target_input.startswith("http"):
            parts = target_input.split("-")
            if len(parts) == 2:
                try:
                    start_ip = ipaddress.ip_address(parts[0].strip())
                    end_val = parts[1].strip()
                    if "." in end_val:
                        end_ip = ipaddress.ip_address(end_val)
                    else:
                        octets = str(start_ip).split(".")
                        octets[-1] = end_val
                        end_ip = ipaddress.ip_address(".".join(octets))
                    
                    start_int = int(start_ip)
                    end_int = int(end_ip)
                    if start_int <= end_int:
                        return [str(ipaddress.ip_address(i)) for i in range(start_int, end_int + 1)]
                except ValueError:
                    pass

        try:
            resolved_ip = socket.gethostbyname(target_input)
            return [resolved_ip]
        except socket.gaierror:
            return []

    @staticmethod
    def parse_port_range(port_arg: str) -> List[int]:
        ports = set()
        for token in port_arg.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                try:
                    start, end = map(int, token.split("-"))
                    start = max(1, min(65535, start))
                    end = max(1, min(65535, end))
                    if start <= end:
                        ports.update(range(start, end + 1))
                except ValueError:
                    continue
            else:
                try:
                    p = int(token)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except ValueError:
                    continue
        return sorted(list(ports))
