IP Info Tool
============

Description:
------------
The IP Info Tool is a web application that provides detailed information about a given IP address. It retrieves WHOIS, DIG, Traceroute, and Nmap scan results using system commands.

Features:
---------
- WHOIS lookup
- DIG command execution
- Traceroute analysis
- Nmap scan (basic)

## Screenshots
![image](https://github.com/user-attachments/assets/a6984e3c-e212-4c8b-9235-4da46b3e62e3)
![image](https://github.com/user-attachments/assets/10a88ff7-23b2-4b3f-865a-b58ae59e6276)

Requirements:
-------------
- Python 3.x
- Flask
- System utilities: whois, dig, traceroute, nmap (must be installed)

Installation:
-------------
1. Clone the repository:
   git clone <repo-url>

2. Navigate to the project directory:
   cd ip-info-tool

3. Install dependencies:
   pip install -r requirements.txt

4. Run the application:
   python app.py

5. Open your browser and go to:
   http://127.0.0.1:5000

Notes:
------
- This tool executes system commands, so ensure the required utilities are installed.
- Running Nmap may require administrative privileges.
- Use responsibly and ensure you have permission before scanning any IP.

Author:
-------
Vedant Dhananjay Kahalekar
