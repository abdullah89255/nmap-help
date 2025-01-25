# nmap-help
Here's an outline of `nmap` usage with examples tailored to various scenarios:

---

## **Basic Syntax**
```bash
nmap [options] [target]
```
- `[target]`: IP address, hostname, or network range (e.g., `192.168.1.0/24`).
- `[options]`: Flags to customize the scan behavior.

---

## **1. Basic Scanning**

### Example: Scan a Single Host
```bash
nmap 192.168.1.1
```
- Scans the target IP and reports open ports and services.

### Example: Scan a Range of IPs
```bash
nmap 192.168.1.1-10
```
- Scans IPs from `192.168.1.1` to `192.168.1.10`.

### Example: Scan an Entire Subnet
```bash
nmap 192.168.1.0/24
```
- Scans all hosts in the subnet.

### Example: Hostname Scan
```bash
nmap example.com
```
- Resolves the hostname and scans the corresponding IP.

---

## **2. Port Scanning**

### Example: Scan Specific Ports
```bash
nmap -p 22,80,443 192.168.1.1
```
- Scans ports 22, 80, and 443 on the target.

### Example: Scan All 65535 Ports
```bash
nmap -p- 192.168.1.1
```
- Performs a comprehensive scan of all ports.

### Example: Fast Scan for Common Ports
```bash
nmap -F 192.168.1.1
```
- Scans only the 100 most common ports.

---

## **3. Service and Version Detection**

### Example: Detect Services on Open Ports
```bash
nmap -sV 192.168.1.1
```
- Identifies services (e.g., HTTP, SSH) running on open ports.

### Example: Aggressive Scan (Service + OS Detection)
```bash
nmap -A 192.168.1.1
```
- Performs service detection, OS detection, and traceroute.

---

## **4. Operating System Detection**

### Example: Basic OS Detection
```bash
nmap -O 192.168.1.1
```
- Attempts to determine the operating system of the target.

### Example: Guess OS Aggressively
```bash
nmap -O --osscan-guess 192.168.1.1
```
- Makes educated guesses about the OS if detection is uncertain.

---

## **5. Network Discovery**

### Example: Ping Sweep
```bash
nmap -sn 192.168.1.0/24
```
- Finds live hosts in the subnet without port scanning.

### Example: Disable Reverse DNS
```bash
nmap -n 192.168.1.0/24
```
- Speeds up scanning by skipping DNS resolution.

### Example: Trace Route
```bash
nmap --traceroute 192.168.1.1
```
- Maps the path packets take to the target.

---

## **6. Script Scanning (NSE)**

### Example: Run Vulnerability Scans
```bash
nmap --script vuln 192.168.1.1
```
- Runs scripts to check for known vulnerabilities.

### Example: Use Specific Scripts
```bash
nmap --script http-enum 192.168.1.1
```
- Uses the `http-enum` script to enumerate web server directories.

---

## **7. Stealth and Evasion**

### Example: TCP SYN Scan (Stealth Scan)
```bash
nmap -sS 192.168.1.1
```
- Sends SYN packets without completing the handshake.

### Example: Scan Slowly to Avoid Detection
```bash
nmap --scan-delay 500ms 192.168.1.1
```
- Adds a delay between probes to reduce suspicion.

### Example: Use a Decoy IP
```bash
nmap -D RND:10 192.168.1.1
```
- Launches the scan with random decoy IPs.

---

## **8. Output Options**

### Example: Save Output to a File
```bash
nmap -oN output.txt 192.168.1.1
```
- Saves human-readable results to `output.txt`.

### Example: Save Machine-Readable Output
```bash
nmap -oX output.xml 192.168.1.1
```
- Exports results in XML format.

### Example: Combine Output Formats
```bash
nmap -oA output 192.168.1.1
```
- Saves results in normal, XML, and script-kiddie formats.

---

## **9. Advanced Scans**

### Example: UDP Scan
```bash
nmap -sU 192.168.1.1
```
- Scans for open UDP ports.

### Example: Scan for Specific Vulnerabilities
```bash
nmap --script smb-vuln-ms17-010 192.168.1.1
```
- Checks if the target is vulnerable to EternalBlue.

### Example: Firewall Detection
```bash
nmap -sA 192.168.1.1
```
- Detects firewall rules and configurations.

---

## **10. Example Scenarios**

### Scenario: Scan a Web Server for Open Ports and Services
```bash
nmap -p 80,443 -sV example.com
```

### Scenario: Scan a Subnet for Live Hosts and Save Results
```bash
nmap -sn 192.168.1.0/24 -oN live_hosts.txt
```

### Scenario: Full Network Audit
```bash
nmap -A -T4 192.168.1.0/24
```
- Performs an aggressive scan on the entire network with normal speed.

---

### Tips
- Use `-T` options to adjust speed (`-T0` for slowest, `-T5` for fastest).
- Always scan responsibly and with permission on networks you own or have explicit authorization to test.

Let me know if you'd like additional details or a specific example!
