from flask import Flask, render_template, request
import os
import socket
from urllib.parse import urlparse

app = Flask(__name__)

def run_command(command):
    result = os.popen(command).read()
    return result

def extract_hostname(input_value):
    input_value = input_value.strip()
    if not input_value.startswith(('http://', 'https://')):
        input_value = 'http://' + input_value
    parsed = urlparse(input_value)
    return parsed.hostname

def resolve_to_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

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
                "whois": run_command(f"whois {ip}"),
                "dig": run_command(f"dig {ip}"),
                "traceroute": run_command(f"traceroute {ip}"),
                "nmap": run_command(f"nmap -Pn {ip}")
            }
        else:
            error = "❌ Could not resolve domain to IP. Please enter a valid IP or domain."
    return render_template('./index.html', data=data, error=error)

if __name__ == '__main__':
    app.run(debug=True)
