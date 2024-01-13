# 08-network-enumeration-with-nmap

## Enumeration

- We look for
    - Functions and/or resources that allow us to interact with the target and/or provide additional information
    - Information that provides us with even more important information to access our target.
- Enumeration is the key.
- Manual enumeration is a critical component.

## Nmap

- open-source network analysis and security auditing tool written in C, C++, Python, and Lua
- use cases
    - Audit the security aspects of networks
    - Simulate penetration tests
    - Check firewall and IDS settings and configurations
    - Types of possible connections
    - Network mapping
    - Response analysis
    - Identify open ports
    - Vulnerability assessment as well.
- Scanning techniques
    - Host discovery
    - Port scanning
    - Service enumeration and detection
    - OS detection
    - Scriptable interaction with the target service (Nmap Scripting Engine)
- TCP-SYN scan (-sS) sends one packet with the SYN flag and, therefore, never completes the three-way handshake,
    - SYN-ACT - open
    - RST - closed
    - does not receive a packet back - it will display as filtered

## Host discovery

- Check if host is alive - ICMP echo requests
- -sn : disables port scanning
    - this method only works if the firewalls of the hosts allow it
- `sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5`
- [https://nmap.org/book/host-discovery-strategies.html](https://nmap.org/book/host-discovery-strategies.html)

## Host and port scanning

- information we need
    - Open ports and its services
    - Service versions
    - Information that the services provided
    - Operating system
- six different states for scanned ports
    - open
    - closed
    - filtered
    - unfiltered
        - state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed.
    - open | filtered
    - closed | filtered
        - This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.
- Discovering Open TCP Ports
    - default - 1000 tcp ports scan with SYN scan (-sS)
    - root - socket permission required to create raw TCP packets
    - otherwise TCP scan (-sT) default
    - all ports `-p-`
    - fast port scan top 100 (-F)
    - To have a clear view of the SYN scan, we disable the ICMP echo requests (-Pn), DNS resolution (-n), and ARP ping scan (--disable-arp-ping).
- Connect Scan
    - (-sT) TCP three-way handshake
    - most accurate
    - and most stealthy
- Filtered Ports
    - firewalls have certain rules set to handle specific connections
    - packet can either be dropped or rejected
    - (—max-tries) is set to 1

## Discovering Open UDP Ports

- UDP scan (-sU)
- If we get an ICMP response with error code 3 (port unreachable), we know that the port is indeed closed.

## Saving the Results

- Formats
    - Normal output (-oN) with the .nmap file extension
    - Grepable output (-oG) with the .gnmap file extension
    - XML output (-oX) with the .xml file extension
        - XMlL to html - `xsltproc target.xml -o target.html`

## Service Enumeration

- (-sV)

```markdown
sudo nmap 10.129.2.28 -p- -sV -Pn -n --disable-arp-ping --packet-trace
sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
nc -nv 10.129.2.28 25
```

## Nmap scripting engine

- 14 categories of script
- `sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands`
- `sudo nmap 10.129.2.28 -p 80 -sV --script vuln`

## Performance

- (-T)
- `sudo nmap 10.129.2.0/24 -F | grep "/tcp" | wc -l`

```markdown
-T 0 / -T paranoid
-T 1 / -T sneaky
-T 2 / -T polite
-T 3 / -T normal
-T 4 / -T aggressive
-T 5 / -T insane
degault -T 3
```

## Firewall and IDS/IPS Evasion

- The dropped packets are ignored, and no response is returned from the host.
- This is different for rejected packets that are returned with an RST flag. These packets contain different types of ICMP error codes or contain nothing at all.
- Nmap's TCP ACK scan (-sA) method is much harder to filter for firewalls and IDS/IPS systems than regular SYN (-sS) or Connect scans (sT) because they only send a TCP packet with only the ACK flag

## Decoys

- (-D)
- With this method, Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent.
- With this method, we can generate random (RND) a specific number (for example: 5) of IP addresses separated by a colon (:)
- sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
- The spoofed packets are often filtered out by ISPs and routers, even though they come from the same network range. Therefore, we can also specify our VPS servers' IP addresses and use them in combination with "IP ID" manipulation in the IP headers to scan the target.
- manually specify the source IP address (-S)
- Testing Firewall Rule
    - `sudo nmap 10.129.2.28 -n -Pn -p445 -O` os detection
- Scan by Using Different Source IP
    - `sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0`
- DNS proxying
    - The DNS queries are made over the UDP port 53
    - we can use TCP port 53 as a source port (--source-port) for our scans
    - SYN-Scan From DNS Port `sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53`
    - `ncat -nv --source-port 53 10.129.2.28 50000`

`nmap -sSU -p 53 --script dns-nsid 10.129.45.239`