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
            jarm_hash = result.get("jarm_hash")
            
            panel_title = f"[bold green]Target: {target}[/bold green]"
            ports_str = ", ".join(map(str, open_ports)) if open_ports else "None"
            panel_content = f"Discovered Open Ports: [bold yellow]{ports_str}[/bold yellow]"
            if jarm_hash:
                panel_content += f"\nJARM TLS Fingerprint: [bold magenta]{jarm_hash}[/bold magenta]"

            self.console.print(Panel(panel_content, title=panel_title, expand=False))

            if not open_ports:
                continue

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Port", style="dim", width=8)
            table.add_column("Protocol / Mode", width=16)
            table.add_column("Handshake / Banner Details", width=36)
            table.add_column("Fingerprinted Stack", width=36)

            for port_detail in result["details"]:
                port_num = str(port_detail["port"])
                is_http = "HTTP/HTTPS" if port_detail["http_data"]["is_http"] else "RAW Socket"
                
                banner = port_detail["raw_socket"]["extracted_version"] or port_detail["raw_socket"]["banner"].strip().replace("\r\n", " ").replace("\n", " ")
                if len(banner) > 35:
                    banner = banner[:35] + "..."
                if not banner and port_detail["http_data"]["is_http"]:
                    server = port_detail["http_data"]["headers"].get("Server") or port_detail["http_data"]["headers"].get("server")
                    banner = f"HTTP Server: {server}" if server else "HTTP Endpoint Active"

                techs = port_detail["technologies"]
                tech_str = ", ".join([f"[bold yellow]{t['name']}[/bold yellow] ({t['version']})" for t in techs])
                if not tech_str:
                    tech_str = "[dim]Unidentified Service[/dim]"

                table.add_row(port_num, is_http, banner or "-", tech_str)

            self.console.print(table)

            # Exploit-DB Matching Results
            exploit_matches = result.get("exploitdb_matches", [])
            if exploit_matches:
                self.console.print("  [bold yellow]⚡ Exploit-DB Offline Matches Discovered:[/bold yellow]")
                for exp in exploit_matches:
                    self.console.print(f"    [red][EDB-ID: {exp['id']}][/red] [white]{exp['description']}[/white] (Path: {exp['file']})")

            # Active Scripts Findings
            script_outputs = result.get("script_outputs", [])
            if script_outputs:
                self.console.print("  [bold red]▶ Active Script Audit Findings:[/bold red]")
                for s_out in script_outputs:
                    p = s_out["port"]
                    s_name = s_out["script_name"]
                    data = s_out["output"]
                    self.console.print(f"    [yellow][Port {p} - {s_name}][/yellow] [bold white]{data.get('issue')}[/bold white]: {data.get('details') or data.get('hosted_models')}")
            self.console.print("\n")
