from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List, Dict, Any

class CLIReporter:
    def __init__(self):
        self.console = Console()

    def print_results(self, scan_results: List[Dict[str, Any]]) -> None:
        self.console.print("\n[bold cyan]=== SPECTER RECONNAISSANCE SCAN RESULTS ===[/bold cyan]\n")

        for result in scan_results:
            target = result["target"]
            open_ports = result["open_ports"]
            
            panel_title = f"[bold green]Target: {target}[/bold green]"
            ports_str = ", ".join(map(str, open_ports)) if open_ports else "None"
            self.console.print(Panel(f"Discovered Open Ports: [bold yellow]{ports_str}[/bold yellow]", title=panel_title, expand=False))

            if not open_ports:
                continue

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Port", style="dim", width=8)
            table.add_column("Protocol / Mode", width=16)
            table.add_column("Banner / Server Header", width=35)
            table.add_column("Fingerprinted Stack", width=40)

            for port_detail in result["details"]:
                port_num = str(port_detail["port"])
                is_http = "HTTP/HTTPS" if port_detail["http_data"]["is_http"] else "RAW Socket"
                
                banner = port_detail["raw_socket"]["banner"].strip().replace("\r\n", " ").replace("\n", " ")
                if len(banner) > 30:
                    banner = banner[:30] + " (truncated)"
                if not banner and port_detail["http_data"]["is_http"]:
                    server = port_detail["http_data"]["headers"].get("Server") or port_detail["http_data"]["headers"].get("server")
                    banner = f"HTTP Server: {server}" if server else "HTTP Endpoint Active"

                techs = port_detail["technologies"]
                tech_str = ", ".join([f"[bold yellow]{t['name']}[/bold yellow] ({t['version']})" for t in techs])
                if not tech_str:
                    tech_str = "[dim]Unidentified Service[/dim]"

                table.add_row(port_num, is_http, banner or "-", tech_str)

            self.console.print(table)
            self.console.print("\n")
