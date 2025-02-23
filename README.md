# Network Scanner (C#)

## Description

This project is a C# network scanner that scans a local network to find active devices and checks for open ports on these devices. It can also check for known vulnerabilities in services running on these devices using CVE information

## Features

- Automatic detection of local IP address
- Scan devices in a local network (subnet 192.168.x.x, 10.x.x.x, 172.x.x.x)
- Ping hosts using ICMP and TCP (ports 80, 443)
- Check open ports on devices (FTP, SSH, Telnet, HTTP and others)
- Check for known vulnerabilities for popular services via NVD API
## Usage
- Run the program.
The program will automatically detect your local IP address and then start scanning all IP addresses in your local network (subnet /24). It checks host activity and open ports
- Expect console output about host status and open ports
## Example output
Your IP: 192.168.1.10

Starting scan in subnet 192.168.1.0/24...

[+] 192.168.1.1 - Online

Scanning ports on 192.168.1.1...

[!] 192.168.1.1:22 - SSH (Open)

⚠ Found vulnerabilities for SSH:
   - CVE-2021-12345: Description of vulnerability
   - CVE-2020-67890: Another vulnerability description
## How does the program work?
- Local IP Address Detection: The program finds the user's local IP address using the GetLocalIPAddress() method
- Network Scanning: The program scans all IP addresses in the subnet (e.g. 192.168.1.1 - 192.168.1.254) using the ScanHost() method, pinging and checking TCP ports 80 (HTTP) and 443 (HTTPS)
- Port Checking: For each active host, the program scans specific ports such as FTP, SSH, HTTP, and others
- Vulnerability Checking: If an open port is found on the host, the program uses the NVD API to check for vulnerabilities on the services running on these ports
