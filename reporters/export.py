import json
import csv
from typing import List, Dict, Any

class ExportManager:
    @staticmethod
    def export_json(scan_data: List[Dict[str, Any]], filepath: str) -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=4, ensure_ascii=False)

    @staticmethod
    def export_csv(scan_data: List[Dict[str, Any]], filepath: str) -> None:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Target", "Port", "Is_HTTP", "Status_Code", "Service_Banner", "Detected_Technologies"])
            for item in scan_data:
                target = item["target"]
                for detail in item["details"]:
                    port = detail["port"]
                    is_http = detail["http_data"]["is_http"]
                    status = detail["http_data"]["status_code"]
                    banner = detail["raw_socket"]["banner"].strip().replace("\n", " ")
                    techs = "; ".join([f"{t['name']}:{t['version']}" for t in detail["technologies"]])
                    writer.writerow([target, port, is_http, status, banner, techs])

    @staticmethod
    def export_html(scan_data: List[Dict[str, Any]], filepath: str) -> None:
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Specter Reconnaissance Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 20px; }
        h1 { color: #38bdf8; border-bottom: 2px solid #0284c7; padding-bottom: 10px; }
        .card { background-color: #1e293b; border-radius: 8px; padding: 15px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #334155; padding: 10px; text-align: left; }
        th { background-color: #0f172a; color: #38bdf8; }
        .badge { background-color: #0284c7; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Specter Reconnaissance Detailed Report</h1>
    <div id="content">
"""
        for item in scan_data:
            ports_list = ", ".join(map(str, item['open_ports'])) if item['open_ports'] else "None"
            html_content += f"""
        <div class="card">
            <h2>Target: {item['target']}</h2>
            <p><strong>Open Ports:</strong> {ports_list}</p>
            <table>
                <tr><th>Port</th><th>Type</th><th>Status</th><th>Banner</th><th>Technologies Detected</th></tr>"""
            for detail in item["details"]:
                techs = "".join([f"<span class='badge'>{t['name']} ({t['version']})</span> " for t in detail['technologies']])
                is_http_str = "HTTP/HTTPS" if detail['http_data']['is_http'] else "RAW Socket"
                banner_preview = detail['raw_socket']['banner'][:50].replace("<", "&lt;").replace(">", "&gt;")
                html_content += f"""
                <tr>
                    <td>{detail['port']}</td>
                    <td>{is_http_str}</td>
                    <td>{detail['http_data']['status_code']}</td>
                    <td><code>{banner_preview}</code></td>
                    <td>{techs}</td>
                </tr>"""
            html_content += "</table></div>"
        
        html_content += "</div></body></html>"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
