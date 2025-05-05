from flask import Flask, render_template, request
import os
import socket
from urllib.parse import urlparse
import requests
import ssl
import shodan
import dns.resolver

app = Flask(__name__)

SHODAN_API_KEY = ""  # Replace with your actual Shodan API key
shodan_api = shodan.Shodan(SHODAN_API_KEY)

def run_command(command):
    return os.popen(command).read()

def extract_hostname(input_value):
    input_value = input_value.strip()
    if not input_value.startswith(('http://', 'https://')):
        input_value = 'http://' + input_value
    return urlparse(input_value).hostname

def resolve_to_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Not available"

def geoip_lookup(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}")
        return r.json()
    except:
        return {}

def get_ssl_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3.0)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            return cert
    except:
        return {}

def get_http_headers(hostname):
    try:
        response = requests.get(f"http://{hostname}", timeout=5)
        return dict(response.headers)
    except:
        return {}

def get_subdomains_crtsh(domain):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        data = r.json()
        subdomains = set()
        for entry in data:
            subdomains.update(entry['name_value'].split("\n"))
        return sorted(subdomains)
    except:
        return []

def get_dns_records(domain):
    records = {}
    try:
        for rtype in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
            answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
            records[rtype] = [r.to_text() for r in answers]
    except:
        pass
    return records

def shodan_lookup(ip):
    try:
        return shodan_api.host(ip)
    except shodan.APIError as e:
        return {"error": str(e)}

@app.route('/', methods=['GET', 'POST'])
def index():
    data = None
    error = None
    if request.method == 'POST':
        user_input = request.form['ip']
        hostname = extract_hostname(user_input)
        ip = resolve_to_ip(hostname)

        if ip:
            data = {
                "resolved_ip": ip,
                "reverse_dns": reverse_dns(ip),
                "geo": geoip_lookup(ip),
                "whois": run_command(f"whois {ip}"),
                "dig": run_command(f"dig {ip}"),
                "traceroute": run_command(f"traceroute {ip}"),
                "nmap": run_command(f"nmap -Pn {ip}"),
                "ssl_info": get_ssl_info(hostname),
                "headers": get_http_headers(hostname),
                "subdomains": get_subdomains_crtsh(hostname),
                "dns_records": get_dns_records(hostname),
                "shodan": shodan_lookup(ip)
            }
        else:
            error = "❌ Could not resolve domain to IP. Please enter a valid IP or domain."

    return render_template('index.html', data=data, error=error)

if __name__ == '__main__':
    app.run(debug=True)
