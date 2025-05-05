from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Union
from urllib.parse import urlparse
import socket
import os
import requests
import ssl
import dns.resolver
import io
import json
import pathlib

app = FastAPI(title="Recon Tool API")

# Mount static folder to serve HTML, CSS, JS
app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve index.html from /static on root path
@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    index_file = pathlib.Path("static/index.html")
    if index_file.exists():
        return index_file.read_text()
    return HTMLResponse(content="Index file not found", status_code=404)

# ---------- Utility Functions ----------

def run_command(command: str) -> str:
    return os.popen(command).read()

def extract_hostname(input_value: str) -> str:
    input_value = input_value.strip()
    if not input_value.startswith(('http://', 'https://')):
        input_value = 'http://' + input_value
    return urlparse(input_value).hostname

def resolve_to_ip(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Not available"

def geoip_lookup(ip: str) -> dict:
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}")
        return r.json()
    except:
        return {}

def get_ssl_info(hostname: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3.0)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            return cert
    except:
        return {}

def get_http_headers(hostname: str) -> dict:
    try:
        response = requests.get(f"http://{hostname}", timeout=5)
        return dict(response.headers)
    except:
        return {}

# Use subfinder to get subdomains
def get_subdomains_subfinder(domain: str) -> List[str]:
    try:
        subfinder_output = run_command(f"subfinder -d {domain} -o -")
        subdomains = subfinder_output.splitlines()
        return subdomains
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain: str) -> Dict[str, List[str]]:
    records = {}
    try:
        for rtype in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
            answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
            records[rtype] = [r.to_text() for r in answers]
    except:
        pass
    return records

# ---------- Pydantic Models ----------

class ReconRequest(BaseModel):
    target: str

class ExportRequest(BaseModel):
    data: dict

# ---------- API Endpoints ----------

@app.post("/api/recon")
async def run_recon(req: ReconRequest):
    hostname = extract_hostname(req.target)
    ip = resolve_to_ip(hostname)

    if not ip:
        raise HTTPException(status_code=400, detail="❌ Could not resolve domain to IP.")

    # Run nmap with SSL and DNS scripts
    nmap_output = run_command(f"nmap -Pn -p 443 --script ssl-cert,dns-brute,dns-zone-transfer,dns-service-discovery {ip}")

    # Get subdomains using subfinder
    subdomains = get_subdomains_subfinder(hostname)

    result = {
        "resolved_ip": ip,
        "reverse_dns": reverse_dns(ip),
        "geo": geoip_lookup(ip),
        "whois": run_command(f"whois {ip}"),
        "dig": run_command(f"dig {ip}"),
        "traceroute": run_command(f"traceroute {ip}"),
        "nmap_scripts": nmap_output,
        "http_headers": get_http_headers(hostname),
        "subdomains": subdomains,
    }

    return result

@app.post("/api/export/txt")
async def export_txt(req: ExportRequest):
    output = io.StringIO()
    for key, value in req.data.items():
        output.write(f"{key.upper()}\n{'='*40}\n")
        output.write(json.dumps(value, indent=2) if not isinstance(value, str) else value)
        output.write("\n\n")
    output.seek(0)
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/plain", headers={"Content-Disposition": "attachment; filename=recon_results.txt"})

@app.post("/api/export/json")
async def export_json(req: ExportRequest):
    content = json.dumps(req.data, indent=2).encode()
    return StreamingResponse(io.BytesIO(content), media_type="application/json", headers={"Content-Disposition": "attachment; filename=recon_results.json"})
