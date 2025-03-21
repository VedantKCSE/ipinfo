from flask import Flask, render_template, request
import os

app = Flask(__name__)

def run_command(command):
    result = os.popen(command).read()
    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    data = None
    if request.method == 'POST':
        ip = request.form['ip']
        data = {
            "whois": run_command(f"whois {ip}"),
            "dig": run_command(f"dig {ip}"),
            "traceroute": run_command(f"traceroute {ip}"),
            "nmap": run_command(f"nmap -Pn {ip}")
        }
    return render_template('./index.html', data=data)

if __name__ == '__main__':
    app.run(debug=True)
