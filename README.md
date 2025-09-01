
# 🔥 Nmap Usage Examples with Details

General syntax:

```bash
nmap [options] <target>
```

---

## 🎯 1–10: Basic Scans
Detect WAF
 ```bash
  nmap -p80,443 --script http-waf-detect bmo.com
   ```
Fingerprint WAF
 ```bash
 nmap -p80,443 --script http-waf-fingerprint bmo.com

   ```

---
1. **Scan a single host**

   ```bash
   nmap 192.168.1.1
   ```

   → Default TCP scan on top 1000 ports.

2. **Scan a hostname**

   ```bash
   nmap scanme.nmap.org
   ```

   → Resolves DNS and scans the host.

3. **Multiple IPs**

   ```bash
   nmap 192.168.1.1 192.168.1.2
   ```

   → Scans two IPs at once.

4. **IP range**

   ```bash
   nmap 192.168.1.1-50
   ```

   → Scans `.1` to `.50`.

5. **CIDR notation**

   ```bash
   nmap 192.168.1.0/24
   ```

   → Scans the entire subnet.

6. **Fast scan (top 100 ports)**

   ```bash
   nmap -F 192.168.1.1
   ```

7. **All 65535 ports**

   ```bash
   nmap -p- 192.168.1.1
   ```

8. **Specific ports**

   ```bash
   nmap -p 22,80,443 192.168.1.1
   ```

9. **Port range**

   ```bash
   nmap -p 1-1000 192.168.1.1
   ```

10. **Exclude hosts**

```bash
nmap 192.168.1.0/24 --exclude 192.168.1.5
```

---

## ⚡ 11–20: Scan Types

11. **TCP SYN scan (default, stealth)**

```bash
nmap -sS 192.168.1.1
```

12. **TCP connect scan**

```bash
nmap -sT 192.168.1.1
```

13. **UDP scan**

```bash
nmap -sU 192.168.1.1
```

14. **TCP + UDP together**

```bash
nmap -sS -sU 192.168.1.1
```

15. **TCP ACK scan**

```bash
nmap -sA 192.168.1.1
```

16. **FIN scan**

```bash
nmap -sF 192.168.1.1
```

17. **NULL scan**

```bash
nmap -sN 192.168.1.1
```

18. **XMAS scan**

```bash
nmap -sX 192.168.1.1
```

19. **Idle scan (spoofed)**

```bash
nmap -sI zombiehost 192.168.1.1
```

20. **Protocol scan**

```bash
nmap -sO 192.168.1.1
```

---

## 🔑 21–30: Service & OS Detection

21. **Service version detection**

```bash
nmap -sV 192.168.1.1
```

22. **Aggressive scan (services + OS + traceroute + scripts)**

```bash
nmap -A 192.168.1.1
```

23. **OS detection**

```bash
nmap -O 192.168.1.1
```

24. **Aggressive OS detection**

```bash
nmap -O --osscan-guess 192.168.1.1
```

25. **Detect service on specific port**

```bash
nmap -sV -p 443 192.168.1.1
```

26. **Run NSE scripts by category (default)**

```bash
nmap --script=default 192.168.1.1
```

27. **Run safe scripts**

```bash
nmap --script=safe 192.168.1.1
```

28. **Run vulnerability scripts**

```bash
nmap --script=vuln 192.168.1.1
```

29. **Run multiple specific scripts**

```bash
nmap --script http-title,dns-brute 192.168.1.1
```

30. **Run scripts from a directory**

```bash
nmap --script /usr/share/nmap/scripts/http* 192.168.1.1
```

---

## 📡 31–40: Host Discovery

31. **Ping scan only (no port scan)**

```bash
nmap -sn 192.168.1.0/24
```

32. **Disable ping (force scan even if host blocks ICMP)**

```bash
nmap -Pn 192.168.1.1
```

33. **ICMP echo discovery**

```bash
nmap -PE 192.168.1.0/24
```

34. **ICMP timestamp discovery**

```bash
nmap -PP 192.168.1.0/24
```

35. **ICMP netmask discovery**

```bash
nmap -PM 192.168.1.0/24
```

36. **ARP discovery (local LAN)**

```bash
nmap -PR 192.168.1.0/24
```

37. **TCP SYN discovery**

```bash
nmap -PS22,80,443 192.168.1.0/24
```

38. **TCP ACK discovery**

```bash
nmap -PA80,443 192.168.1.0/24
```

39. **UDP discovery**

```bash
nmap -PU53,161 192.168.1.0/24
```

40. **Traceroute**

```bash
nmap --traceroute 192.168.1.1
```

---

## 📂 41–50: Output & Reporting

41. **Normal output to file**

```bash
nmap -oN scan.txt 192.168.1.1
```

42. **XML output**

```bash
nmap -oX scan.xml 192.168.1.1
```

43. **Grepable output**

```bash
nmap -oG scan.gnmap 192.168.1.1
```

44. **All formats at once**

```bash
nmap -oA results 192.168.1.1
```

→ Saves `.nmap`, `.xml`, `.gnmap`.

45. **Append output**

```bash
nmap -oN scan.txt --append-output 192.168.1.2
```

46. **Increase verbosity**

```bash
nmap -v 192.168.1.1
```

47. **Maximum verbosity**

```bash
nmap -vv 192.168.1.1
```

48. **Debug mode**

```bash
nmap -d 192.168.1.1
```

49. **Packet trace**

```bash
nmap --packet-trace 192.168.1.1
```

50. **Reason for results**

```bash
nmap --reason 192.168.1.1
```
## 🚀 51–60: Performance & Timing

51. **Increase speed (aggressive timing)**

```bash
nmap -T4 192.168.1.1
```

52. **Max speed (not stealthy)**

```bash
nmap -T5 192.168.1.1
```

53. **Slow timing (stealthy)**

```bash
nmap -T1 192.168.1.1
```

54. **Custom max retries**

```bash
nmap --max-retries 2 192.168.1.1
```

55. **Custom host timeout**

```bash
nmap --host-timeout 30s 192.168.1.1
```

56. **Parallelism (max probes)**

```bash
nmap --max-parallelism 10 192.168.1.1
```

57. **Custom scan delay**

```bash
nmap --scan-delay 500ms 192.168.1.1
```

58. **Random scan order**

```bash
nmap --randomize-hosts 192.168.1.0/24
```

59. **Fragment packets (evade IDS)**

```bash
nmap -f 192.168.1.1
```

60. **Send decoy traffic**

```bash
nmap -D RND:5 192.168.1.1
```

➡ Sends 5 random decoys to mask your IP.

---

## 🕵️ 61–70: Firewall / IDS Evasion

61. **Source port trick (FTP 20)**

```bash
nmap --source-port 20 192.168.1.1
```

62. **Append custom data payload**

```bash
nmap --data-length 50 192.168.1.1
```

63. **Send bogus TCP options**

```bash
nmap --ip-options "R" 192.168.1.1
```

64. **Bad checksum packets**

```bash
nmap --badsum 192.168.1.1
```

65. **Scan through proxy (SOCKS4)**

```bash
nmap --proxies socks4://127.0.0.1:9050 192.168.1.1
```

66. **MAC address spoofing**

```bash
nmap --spoof-mac 0 192.168.1.1
```

67. **Custom TTL**

```bash
nmap --ttl 50 192.168.1.1
```

68. **Send IP packets only**

```bash
nmap -sP --send-ip 192.168.1.0/24
```

69. **Force no DNS resolution**

```bash
nmap -n 192.168.1.1
```

70. **Custom MTU**

```bash
nmap --mtu 32 192.168.1.1
```

---

## 🔍 71–80: NSE (Nmap Scripting Engine)

71. **SSL certificate info**

```bash
nmap --script ssl-cert -p 443 example.com
```

72. **SSL weak ciphers**

```bash
nmap --script ssl-enum-ciphers -p 443 example.com
```

73. **Find HTTP titles**

```bash
nmap --script http-title -p 80,443 example.com
```

74. **Check for WAF**

```bash
nmap --script http-waf-detect -p80,443 example.com
```

75. **Fingerprint WAF**

```bash
nmap --script http-waf-fingerprint -p80,443 example.com
```

76. **WordPress detection**

```bash
nmap --script http-wordpress-enum -p80 example.com
```

77. **MySQL enumeration**

```bash
nmap --script mysql-info -p3306 192.168.1.1
```

78. **DNS brute force**

```bash
nmap --script dns-brute example.com
```

79. **SMB OS discovery**

```bash
nmap --script smb-os-discovery -p445 192.168.1.1
```

80. **Vulnerability check**

```bash
nmap --script vuln 192.168.1.1
```

---

## 🖥️ 81–90: Web & Service Scanning

81. **HTTP methods allowed**

```bash
nmap --script http-methods -p80 example.com
```

82. **HTTP headers**

```bash
nmap --script http-headers -p80 example.com
```

83. **Check HTTP robots.txt**

```bash
nmap --script http-robots.txt -p80 example.com
```

84. **Detect open proxy**

```bash
nmap --script http-open-proxy -p8080 example.com
```

85. **FTP anonymous login**

```bash
nmap --script ftp-anon -p21 192.168.1.1
```

86. **SSH version**

```bash
nmap -sV -p22 192.168.1.1
```

87. **SNMP info**

```bash
nmap -sU -p161 --script snmp-info 192.168.1.1
```

88. **NTP monlist (reflection attack check)**

```bash
nmap -sU -p123 --script ntp-monlist 192.168.1.1
```

89. **Check for open MongoDB**

```bash
nmap -p27017 --script mongodb-info 192.168.1.1
```

90. **Check Redis service**

```bash
nmap -p6379 --script redis-info 192.168.1.1
```

---

## 📂 91–100: Reporting & Misc

91. **Scan and output grepable results**

```bash
nmap -oG scan.gnmap 192.168.1.0/24
```

92. **Save XML + import into other tools**

```bash
nmap -oX scan.xml 192.168.1.0/24
```

93. **Convert XML to HTML report**

```bash
xsltproc scan.xml -o report.html
```

94. **Combine outputs**

```bash
nmap -oA fullscan 192.168.1.1
```

95. **Verbose traceroute scan**

```bash
nmap -A --traceroute 192.168.1.1
```

96. **Check for specific vulnerability (Heartbleed)**

```bash
nmap --script ssl-heartbleed -p443 example.com
```

97. **Save only open ports**

```bash
nmap --open 192.168.1.1
```

98. **Use input file with list of hosts**

```bash
nmap -iL hosts.txt
```

99. **Generate random targets**

```bash
nmap -iR 10
```

100. **Check firewall rules (ACK scan)**

```bash
nmap -sA 192.168.1.1
```

---





