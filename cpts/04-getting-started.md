# 04-getting-started

## General

- [https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-methodology](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-methodology)
- Specialisations
    - Network and infrastructure security
    - Application security
    - Security testing
    - Systems auditing
    - Business continuity planning
    - Digital forensics
    - Incident detection and response
- Risk Management Process
    - Identifying the risk
    - Analyse the risk
    - Evaluate the risk
    - Dealing with risk
    - Monitoring risk
- While pentesting make sure to take notes on platform which doesnot sync with cloud (clients sensitive information)

```powershell
sudo openvpn file.ovpn
ifconfig #show tun adapter 
netstat -rn #shows us networks accessible via the VPN
```

## Common terms

- Shell
    - Reverse Shell - Initiates a connection back to a "listener" on our attack box.
    - Bind Shell - "Binds" to a specific port on the target host and waits for a connection from our attack box.
    - Web Shell - Runs operating system commands via the web browser
- [https://www.stationx.net/common-ports-cheat-sheet/](https://www.stationx.net/common-ports-cheat-sheet/)
- [https://packetlife.net/media/library/23/common-ports.pdf](https://packetlife.net/media/library/23/common-ports.pdf)

## Basic Tools

- Netcat, ncat, or nc, is an excellent network utility for interacting with TCP/UDP ports.
- Banner grabbing using SSH
- Tool - socat
- [https://academy.hackthebox.com/module/77/section/726](https://academy.hackthebox.com/module/77/section/726)