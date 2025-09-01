
# 🔥 Nmap Usage – 50 Examples with Details

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

---



👉 Do you want me to also create a **printable PDF cheat sheet (Command | Description)** for both **Nmap (50)** and **Dirsearch (50)** so you can keep them handy in Kali?
