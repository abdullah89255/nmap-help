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

Here are **more advanced and unique examples** of Nmap usage to help you explore its full potential:  

---

# **Unique and Advanced Nmap Examples**

### **1. Scan for Devices with Open SMB Shares**
```bash
nmap --script smb-enum-shares -p 445 192.168.1.0/24
```
- **What It Does:** Detects shared folders on devices using SMB.

---

### **2. Detect SSL/TLS Versions**
```bash
nmap --script ssl-enum-ciphers -p 443 example.com
```
- **What It Does:** Lists supported SSL/TLS ciphers and checks for weak protocols like SSLv3.

---

### **3. Enumerate Open FTP Servers**
```bash
nmap --script ftp-anon,ftp-bounce -p 21 192.168.1.0/24
```
- **What It Does:** Checks for anonymous access and FTP bounce vulnerabilities.

---

### **4. Detect Misconfigured DNS Servers**
```bash
nmap --script dns-recursion -p 53 192.168.1.0/24
```
- **What It Does:** Finds DNS servers allowing unauthorized recursion.

---

### **5. Find Vulnerable Apache Servers**
```bash
nmap --script http-apache-server-status -p 80,443 192.168.1.0/24
```
- **What It Does:** Enumerates Apache server status pages that could expose sensitive data.

---

### **6. Extract SSH Keys**
```bash
nmap --script ssh-hostkey -p 22 192.168.1.1
```
- **What It Does:** Extracts SSH host keys for analysis.

---

### **7. Check for Default SNMP Community Strings**
```bash
nmap --script snmp-brute -p 161 192.168.1.0/24
```
- **What It Does:** Attempts common SNMP community strings to find misconfigurations.

---

### **8. Scan for Proxy Servers**
```bash
nmap --script socks-open-proxy -p 1080 192.168.1.0/24
```
- **What It Does:** Detects SOCKS proxy servers that allow unrestricted access.

---

### **9. HTTP Brute Force Login**
```bash
nmap --script http-brute -p 80,443 192.168.1.10
```
- **What It Does:** Performs brute force attacks on HTTP login forms.

---

### **10. Enumerate Telnet Servers**
```bash
nmap --script telnet-encryption -p 23 192.168.1.0/24
```
- **What It Does:** Checks Telnet servers for encryption and security weaknesses.

---

### **11. Check for SQL Injection Vulnerabilities**
```bash
nmap --script http-sql-injection -p 80 example.com
```
- **What It Does:** Attempts SQL injection on web applications.

---

### **12. Detect Heartbleed Vulnerability**
```bash
nmap --script ssl-heartbleed -p 443 example.com
```
- **What It Does:** Checks if the server is vulnerable to Heartbleed (CVE-2014-0160).

---

### **13. Scan IoT Devices for Exploits**
```bash
nmap --script=http-iot-info 192.168.1.0/24
```
- **What It Does:** Gathers information on IoT devices for security assessments.

---

### **14. Check Firewall Rules with Idle Scan**
```bash
nmap -sI zombie_host 192.168.1.1
```
- **What It Does:** Uses a "zombie" machine to scan a target, bypassing firewalls and leaving no trace on the originating system.

---

### **15. Identify Malware-Hosting Websites**
```bash
nmap --script=http-malware-host 192.168.1.10
```
- **What It Does:** Detects malicious content hosted on HTTP servers.

---

### **16. Detect Weak SSH Passwords**
```bash
nmap --script ssh-brute -p 22 192.168.1.10
```
- **What It Does:** Performs a brute force attack to test weak SSH passwords.

---

### **17. Scan for Ransomware-Exposed Ports**
```bash
nmap -p 3389,445 --script vuln 192.168.1.0/24
```
- **What It Does:** Checks for vulnerabilities in RDP and SMB services that ransomware exploits.

---

### **18. Extract Website Technologies**
```bash
nmap --script http-headers,http-technologies -p 80 example.com
```
- **What It Does:** Extracts web server headers and identifies backend technologies.

---

### **19. Identify Virtual Machines**
```bash
nmap --script=sniffer-detect -p 22,80,443 192.168.1.0/24
```
- **What It Does:** Attempts to detect virtualized environments (e.g., VMware, VirtualBox).

---

### **20. Test Database Servers for Exploits**
```bash
nmap --script=mysql-vuln-cve2012-2122 -p 3306 192.168.1.10
```
- **What It Does:** Tests MySQL servers for a specific CVE vulnerability.

---

## **Chained Examples**

### **Combining Nmap with NSE Scripts**
Scan for all HTTP vulnerabilities:
```bash
nmap --script "http-*" -p 80,443 example.com
```
- **What It Does:** Runs all HTTP-related scripts, identifying misconfigurations, vulnerabilities, and features.

---

### **Automated Recon Workflow**
1. **Step 1:** Discover live hosts.
   ```bash
   nmap -sn 192.168.1.0/24 -oG live_hosts.txt
   ```

2. **Step 2:** Scan open ports of live hosts.
   ```bash
   nmap -iL live_hosts.txt -p- -oN detailed_scan.txt
   ```

3. **Step 3:** Perform vulnerability scans on critical services.
   ```bash
   nmap --script vuln -p 22,80,443 -iL live_hosts.txt -oN vuln_scan.txt
   ```

---

## **Expert Tips**

1. **Use Randomized Scanning**
   To make scanning patterns less predictable:
   ```bash
   nmap -T4 --randomize-hosts 192.168.1.0/24
   ```

2. **Limit Bandwidth for Large Scans**
   To avoid disrupting networks:
   ```bash
   nmap --min-rate 100 --max-rate 1000 192.168.1.0/24
   ```

3. **Save Output for Later Analysis**
   Use multiple output formats:
   ```bash
   nmap -oA scan_results 192.168.1.0/24
   ```
   This generates `.nmap`, `.xml`, and `.gnmap` files.

4. **Visualize Results**
   Use tools like **Zenmap** or import results into visualization platforms (e.g., Splunk).

---



# **More Advanced Nmap Examples**

### **1. Advanced Host Discovery**
#### **Ping Sweep on a Network**
```bash
nmap -sn 192.168.1.0/24
```
- **What It Does:** Lists live hosts without scanning their ports.

#### **ARP Scan for Local Subnet**
```bash
nmap -PR 192.168.1.0/24
```
- **What It Does:** Uses ARP requests to discover hosts on a local Ethernet network. Faster and more reliable than ICMP.

#### **Discover Hosts Using a Specific Interface**
```bash
nmap -e eth0 -sn 192.168.1.0/24
```
- **What It Does:** Uses the specified network interface (`eth0`) for host discovery.

---

### **2. Customized Port Scanning**
#### **Scan Specific High-Risk Ports**
```bash
nmap -p 21,22,23,25,80,443,3389 192.168.1.10
```
- **What It Does:** Scans commonly exploited ports for a specific host.

#### **Scan All 65,535 Ports**
```bash
nmap -p- 192.168.1.10
```
- **What It Does:** Performs a comprehensive port scan for all possible TCP ports.

#### **Scan Top 100 Common Ports**
```bash
nmap --top-ports 100 192.168.1.10
```
- **What It Does:** Scans the 100 most frequently used ports for quick results.

---

### **3. Detect Network Infrastructure**
#### **Trace Network Path**
```bash
nmap --traceroute 192.168.1.1
```
- **What It Does:** Maps the path packets take to reach the target host.

#### **Scan for Router/Firewall Detection**
```bash
nmap -sA 192.168.1.1
```
- **What It Does:** Identifies devices acting as routers or firewalls by checking packet responses.

#### **Find Network Hops**
```bash
nmap --ttl 1-20 192.168.1.1
```
- **What It Does:** Adjusts the Time-To-Live (TTL) to identify intermediate devices.

---

### **4. Service Detection and Vulnerabilities**
#### **Detect Insecure Default Configurations**
```bash
nmap --script default 192.168.1.1
```
- **What It Does:** Uses default NSE scripts to identify common misconfigurations.

#### **Check Vulnerable NTP Servers**
```bash
nmap --script ntp-monlist -p 123 192.168.1.0/24
```
- **What It Does:** Checks for NTP servers vulnerable to amplification attacks.

#### **Find Shellshock Vulnerability**
```bash
nmap --script http-shellshock -p 80,443 example.com
```
- **What It Does:** Tests for Shellshock vulnerability on web servers.

---

### **5. Evasion Techniques**
#### **Scan Using Decoy IPs**
```bash
nmap -D RND:5 192.168.1.10
```
- **What It Does:** Uses 5 random decoy IPs to mask the true source of the scan.

#### **Randomize Host Order**
```bash
nmap --randomize-hosts 192.168.1.0/24
```
- **What It Does:** Randomizes the order of IPs scanned to avoid detection.

#### **Fragment Packets**
```bash
nmap -f 192.168.1.10
```
- **What It Does:** Sends fragmented packets to bypass firewalls and IDS/IPS systems.

---

### **6. IoT and SCADA System Scanning**
#### **Scan for Open IP Cameras**
```bash
nmap --script http-open-proxy -p 80,8080 192.168.1.0/24
```
- **What It Does:** Detects open web interfaces of IP cameras or proxies.

#### **Identify SCADA Systems**
```bash
nmap --script scada-info -p 502 192.168.1.0/24
```
- **What It Does:** Finds Modbus or other SCADA-related devices on the network.

#### **Detect Smart TVs or Printers**
```bash
nmap -O --osscan-guess 192.168.1.0/24
```
- **What It Does:** Uses OS detection to identify smart devices or printers.

---

### **7. Email Server Enumeration**
#### **Check for Open SMTP Relays**
```bash
nmap --script smtp-open-relay -p 25 192.168.1.10
```
- **What It Does:** Tests if an SMTP server is configured as an open relay.

#### **Enumerate Mail Server Users**
```bash
nmap --script smtp-enum-users -p 25 192.168.1.10
```
- **What It Does:** Attempts to enumerate valid users on an SMTP server.

---

### **8. Wi-Fi and Wireless Device Scanning**
#### **Scan for Wireless Access Points**
```bash
nmap --script wifi-access-point 192.168.1.0/24
```
- **What It Does:** Identifies wireless access points and their SSIDs.

#### **Detect Rogue APs**
```bash
nmap --script http-wifi-rogue -p 80,443 192.168.1.0/24
```
- **What It Does:** Detects unauthorized or rogue wireless access points on the network.

---

### **9. Advanced Script Usage**
#### **Find Web App Vulnerabilities**
```bash
nmap --script http-vuln-* -p 80,443 example.com
```
- **What It Does:** Runs all scripts that target web application vulnerabilities.

#### **Find Misconfigured FTP Servers**
```bash
nmap --script ftp-vsftpd-backdoor -p 21 192.168.1.10
```
- **What It Does:** Detects backdoors in vulnerable FTP servers.

#### **Identify Weak RDP Configurations**
```bash
nmap --script rdp-enum-encryption -p 3389 192.168.1.10
```
- **What It Does:** Tests RDP servers for weak or outdated encryption protocols.

---

### **10. Scan Performance Tuning**
#### **Speed Up Large Network Scans**
```bash
nmap -T4 --min-parallelism 10 --max-retries 1 192.168.1.0/24
```
- **What It Does:** Adjusts timing and parallelism for faster scans.

#### **Save Bandwidth During Scans**
```bash
nmap --min-rate 50 --max-rate 500 192.168.1.0/24
```
- **What It Does:** Limits the number of packets sent per second.

#### **Split Large Scans into Smaller Parts**
```bash
nmap -iL targets_part1.txt -p 22,80,443
```
- **What It Does:** Scans a subset of targets from a list file (`targets_part1.txt`).

---

### **11. Scanning in Hybrid Environments**
#### **Scan Cloud Environments**
```bash
nmap --script cloud-vuln-check -p 80,443 cloud.example.com
```
- **What It Does:** Detects common misconfigurations in cloud-based services.

#### **Detect Virtual Machines**
```bash
nmap --script vmware-version -p 443 192.168.1.0/24
```
- **What It Does:** Identifies virtual machines running VMware.

---

### **12. Fun and Experimental Scripts**
#### **Test Bitcoin Nodes**
```bash
nmap --script bitcoin-info -p 8333 192.168.1.0/24
```
- **What It Does:** Scans for Bitcoin nodes and retrieves blockchain information.

#### **Scan for Tor Exit Nodes**
```bash
nmap --script tor-consensus-check -p 9050 192.168.1.0/24
```
- **What It Does:** Identifies Tor exit nodes in your network.

---

Nmap is packed with advanced features that go beyond basic port scanning, making it a Swiss Army knife for network exploration, security auditing, and penetration testing. As of March 03, 2025, its capabilities have evolved with updates, but the core advanced features remain highly relevant. I’ll dive into some of the most powerful ones, explain what they do, and give practical examples. These assume you’ve got Nmap installed and are comfortable with basic commands like nmap <target>.
1. Scripting Engine (NSE)
The Nmap Scripting Engine lets you run pre-built or custom Lua scripts to automate tasks like vulnerability detection, service enumeration, and brute-forcing.
How It Works: Scripts are stored in the scripts directory (e.g., /usr/share/nmap/scripts/ on Linux) and triggered with --script.
Key Options:
--script <script-name>: Run a specific script.
--script-args: Pass arguments to scripts.
--script category: Run all scripts in a category (e.g., vuln, exploit, auth).
Example: Check for vulnerabilities on a web server:  
nmap -p 80,443 --script vuln <target>
This runs all vulnerability-detection scripts against HTTP/HTTPS ports.
Power Move: Use http-enum to fingerprint web apps:  
nmap -p 80 --script http-enum <target>
It might reveal directories like /admin or /login.
Custom Scripts: Write your own for specific needs (e.g., checking custom headers). Check nmap.org/nsedoc/ for docs.
2. OS Detection
Nmap can fingerprint a target’s operating system and version based on TCP/IP stack behavior.
How It Works: Analyzes responses to crafted packets (e.g., TCP window size, options).
Flag: -O
Example:  
nmap -O <target>
Output might show: "Running: Linux 5.X" or "Windows Server 2019."
Advanced Twist: Combine with version detection:  
nmap -O -sV <target>
This pairs OS info with service versions (e.g., "Apache 2.4.52").
3. Version Detection
Nmap probes open ports to identify running services and their versions, critical for finding outdated software.
Flag: -sV
Options:
--version-intensity <0-9>: Higher numbers (default 7) try harder but take longer.
--version-all: Max intensity (9).
Example:  
nmap -sV -p 22,80 <target>
Might return: "22/tcp open ssh OpenSSH 8.9p1" or "80/tcp open http nginx 1.18.0."
Use Case: Spot exploitable versions (e.g., old SSH or HTTP servers).
4. Aggressive Scanning
The -A flag combines OS detection, version detection, script scanning, and traceroute in one go.
Example:  
nmap -A <target>
Output includes ports, services, OS guesses, and NSE results—verbose but thorough.
Caution: Loud and detectable by IDS/IPS. Use sparingly on sensitive networks.
5. Firewall/IDS Evasion
Nmap offers techniques to bypass firewalls or avoid detection.
Key Options:
-f: Fragment packets to confuse firewalls.
--mtu <size>: Set custom packet size (e.g., --mtu 24).
-D <decoy1,decoy2,...>: Spoof scans from fake IPs.
--source-port <port>: Use a specific source port (e.g., 53 for DNS).
-sI <zombie>: Idle scan using a "zombie" host.
Example: Fragmented scan:  
nmap -f <target>
Stealth Example: Decoy scan:  
nmap -D 8.8.8.8,1.1.1.1 <target>
Makes it look like Google or Cloudflare is scanning too.
Idle Scan:  
nmap -sI <zombie-ip> <target>
Hides your IP entirely if the zombie is idle and exploitable.
6. Timing and Performance
Control scan speed and parallelism for efficiency or stealth.
Flags: -T<0-5>
-T0: Paranoid (super slow, evasive).
-T3: Normal (default).
-T5: Insane (fast, loud).
Custom Tuning:
--min-rate <packets/sec>: Minimum packet rate.
--max-retries <num>: Limit retransmissions.
Example: Fast scan:  
nmap -T4 --min-rate 1000 <target>
7. Output Customization
Save and analyze results in various formats.
Flags:
-oN <file>: Normal output.
-oX <file>: XML (great for tools like Metasploit).
-oG <file>: Grepable format.
-oA <basename>: All formats.
Example:  
nmap -A -oA scan_results <target>
Creates scan_results.nmap, .xml, and .gnmap.
8. IPv6 Support
Scan IPv6 networks with -6.
Example:  
nmap -6 <ipv6-address>
Works with most features (e.g., -sV, -A).
9. Port Specification and Scanning Types
Beyond basic TCP SYN scans (-sS), Nmap supports:
-sU: UDP scan (e.g., for DNS, SNMP).
-sT: TCP connect scan (if you can’t use raw packets).
-p <range>: Custom ports.
Example: Scan UDP and specific TCP ports:  
nmap -sU -sS -p U:53,161,T:22,80 <target>
10. Vulnerability Exploitation (NSE)
Some NSE scripts actively test for exploits (use legally!).
Example: Check for MS17-010 (EternalBlue):  
nmap --script smb-vuln-ms17-010 -p445 <target>
Practical Combo
For a deep dive on a target:  
nmap -T4 -A --script vuln -p- -oA full_scan <target>
Scans all ports (-p-), aggressively (-A), runs vuln scripts, and saves everything.
These features make Nmap a beast for advanced users. Always use ethically and with permission—scanning networks you don’t own or have authorization for can get you in hot water. Which feature are you most interested in trying? I can walk you through it!
