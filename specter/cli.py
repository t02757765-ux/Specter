import argparse
import asyncio
import sys
from rich.console import Console
from specter.config import Config
from specter.core.target import TargetResolver
from specter.core.rate_limiter import RateLimiter
from specter.core.scanner import PortScanner
from specter.probes.raw_socket import RawSocketProbe
from specter.probes.http_probe import HTTPProbe
from specter.probes.jarm import JARMProbe
from specter.exploitdb.indexer import ExploitDBIndexer
from specter.scripts.engine import ScriptEngine
from specter.signatures.matcher import SignatureMatcher
from specter.reporters.cli_reporter import CLIReporter
from specter.reporters.export import ExportManager

console = Console()

def verbose_logger(msg: str) -> None:
    console.print(f"[dim style='italic gray']{msg}[/dim style='italic gray']")

async def run_specter(args: argparse.Namespace) -> None:
    config = Config.load_from_file(args.config) if args.config else Config({})
    
    if args.timeout: 
        config.timeout = args.timeout
    if args.concurrency: 
        config.max_concurrency = args.concurrency
    if args.rate_limit: 
        config.rate_limit = args.rate_limit

    log_cb = verbose_logger if args.verbose else None

    targets = TargetResolver.resolve_target(args.target)
    if not targets:
        console.print(f"[bold red][-] Error: Could not resolve target {args.target}[/bold red]")
        sys.exit(1)

    ports = TargetResolver.parse_port_range(args.ports) if args.ports else config.default_ports

    rate_limiter = RateLimiter(config.rate_limit)
    scanner = PortScanner(config.max_concurrency, config.timeout, rate_limiter, config.retries, verbose_cb=log_cb)
    raw_probe = RawSocketProbe(config.timeout, verbose_cb=log_cb)
    http_probe = HTTPProbe(config.timeout, config.user_agent, verbose_cb=log_cb)
    jarm_probe = JARMProbe(config.timeout, verbose_cb=log_cb)
    script_engine = ScriptEngine(verbose_cb=log_cb)
    matcher = SignatureMatcher()

    # Exploit-DB Offline Indexer Setup
    edb_indexer = None
    if args.exploitdb:
        edb_indexer = ExploitDBIndexer(config.exploitdb_csv)
        if edb_indexer.loaded:
            if args.verbose:
                console.print(f"[bold green][+] Exploit-DB Database loaded: {len(edb_indexer.exploits)} entries.[/bold green]")
        else:
            console.print(f"[bold red][-] Warning: Exploit-DB CSV file ({config.exploitdb_csv}) not found.[/bold red]")

    all_scan_results = []

    for ip in targets:
        if args.verbose:
            console.print(f"[bold blue][*] Starting scan sequence against {ip}...[/bold blue]")

        open_ports = await scanner.scan_target(ip, ports)
        target_detail = {
            "target": ip,
            "open_ports": open_ports,
            "jarm_hash": None,
            "details": [],
            "exploitdb_matches": [],
            "script_outputs": []
        }

        # 1. Salesforce JARM TLS Scan
        if any(p in open_ports for p in (443, 8443, 9443)):
            ssl_port = 443 if 443 in open_ports else [p for p in open_ports if p in (8443, 9443)][0]
            jarm_hash = await jarm_probe.scan_jarm(ip, ssl_port)
            target_detail["jarm_hash"] = jarm_hash

        for port in open_ports:
            raw_res = await raw_probe.execute_probe(ip, port)
            
            scheme = "https" if port in (443, 8443) else "http"
            base_url = f"{scheme}://{ip}:{port}"
            http_res = await http_probe.analyze_url(base_url, config.http_endpoints)

            techs = matcher.match(raw_res, http_res)

            target_detail["details"].append({
                "port": port,
                "raw_socket": raw_res,
                "http_data": http_res,
                "technologies": techs
            })

            # Exploit-DB Matches Lookup
            if edb_indexer and edb_indexer.loaded:
                for t in techs:
                    matches = edb_indexer.search_exploits(t["name"], t["version"])
                    for m in matches:
                        if not any(e["id"] == m["id"] for e in target_detail["exploitdb_matches"]):
                            target_detail["exploitdb_matches"].append(m)

        # Active Scripting Engine Execution
        if args.run_scripts and open_ports:
            if args.verbose:
                console.print(f"[bold green][*] Triggering Active Script Engine for {ip}...[/bold green]")
            script_finds = await script_engine.run_scripts_for_target(ip, target_detail["details"])
            target_detail["script_outputs"] = script_finds

        all_scan_results.append(target_detail)

    # Output Rendering
    cli_reporter = CLIReporter()
    cli_reporter.print_results(all_scan_results)

    # File Exports
    if args.json:
        ExportManager.export_json(all_scan_results, args.json)
        console.print(f"[bold green][+] JSON report saved to {args.json}[/bold green]")
    if args.csv:
        ExportManager.export_csv(all_scan_results, args.csv)
        console.print(f"[bold green][+] CSV report saved to {args.csv}[/bold green]")
    if args.html:
        ExportManager.export_html(all_scan_results, args.html)
        console.print(f"[bold green][+] HTML report saved to {args.html}[/bold green]")

def main() -> None:
    parser = argparse.ArgumentParser(description="Specter: Deep Asynchronous Reconnaissance Engine")
    parser.add_argument("-t", "--target", required=True, help="Target IP, Range (192.168.1.1-10), CIDR, or Domain")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 80,443,3306,445)")
    parser.add_argument("-c", "--concurrency", type=int, help="Max Async Concurrency")
    parser.add_argument("-r", "--rate-limit", type=int, help="Rate limit (packets/sec)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging output")
    parser.add_argument("--run-scripts", action="store_true", help="Enable active audit scripts")
    parser.add_argument("--exploitdb", action="store_true", help="Enable Exploit-DB offline CVE lookup")
    parser.add_argument("--timeout", type=float, help="Socket timeout in seconds")
    parser.add_argument("--config", help="Path to config.yaml")
    parser.add_argument("--json", help="Path to save JSON output")
    parser.add_argument("--csv", help="Path to save CSV output")
    parser.add_argument("--html", help="Path to save HTML output")

    args = parser.parse_args()
    asyncio.run(run_specter(args))

if __name__ == "__main__":
    main()
