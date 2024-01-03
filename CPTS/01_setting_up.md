# Setting up

## General

- firefox sync all addons and bookmarks
- Password manager
    - Complexity
    - Re-usage
    - Remembering
    - Commonly used passwords - [https://nordpass.com/most-common-passwords-list/](https://nordpass.com/most-common-passwords-list/)
    - Bitwarden
- Information that need to be noted
    - Newly discovered information
    - Ideas for further tests and processing
    - Scan results
    - Logging
    - Screenshots
- Note taking tools
    - [Notion.so](http://notion.so/)
    - Xmind
    - Obsidian
- Tools documentation
    - Ghostwriter
    - pwndoc
- Tools logging
    - script
    - date
    - To display the date and time, we can replace the PS1 variable in our .bashrc file with the following content.

```jsx
PS1="\\[\\033[1;32m\\]\\342\\224\\200\\$([[ \\$(/opt/vpnbash.sh) == *\\"10.\\"* ]] && echo \\"[\\[\\033[1;34m\\]\\$(/opt/vpnserver.sh)\\[\\033[1;32m\\]]\\342\\224\\200[\\[\\033[1;37m\\]\\$(/opt/vpnbash.sh)\\[\\033[1;32m\\]]\\342\\224\\200\\")[\\[\\033[1;37m\\]\\u\\[\\033[01;32m\\]@\\[\\033[01;34m\\]\\h\\[\\033[1;32m\\]]\\342\\224\\200[\\[\\033[1;37m\\]\\w\\[\\033[1;32m\\]]\\n\\[\\033[1;32m\\]\\342\\224\\224\\342\\224\\200\\342\\224\\200\\342\\225\\274 [\\[\\e[01;33m\\]$(date +%D-%r)\\[\\e[01;32m\\]]\\\\$ \\[\\e[0m\\]

```

- script (for Linux) and Start-Transcript (for Windows)
- Tool screenshot
    - Flameshot
    - Peek - gifs
- Virtualisation tools
    - VM
    - Docker
    - Vagrant -manage VM

## Linux

Repo

```jsx
/etc/apt/sources.list

```

In Parrot

```jsx
/etc/apt/sources.list.d/parrot.list

```

Update

```jsx
sudo apt update -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y

```

```jsx
sudo apt install $(cat tools.list | tr "\\n" " ") -y

```

### Tmux

```jsx
tmux new -s name  #tmux session
#prefix key ctrl + b => new window
#create tab in window ctrl+b c

```

### Tools

- bashrchgenerator

```jsx
echo 'export PS1="-[\\[$(tput sgr0)\\]\\[\\033[38;5;10m\\]\\d\\[$(tput sgr0)\\]-\\[$(tput sgr0)\\]\\[\\033[38;5;10m\\]\\t\\[$(tput sgr0)\\]]-[\\[$(tput sgr0)\\]\\[\\033[38;5;214m\\]\\u\\[$(tput sgr0)\\]@\\[$(tput sgr0)\\]\\[\\033[38;5;196m\\]\\h\\[$(tput sgr0)\\]]-\\n-[\\[$(tput sgr0)\\]\\[\\033[38;5;33m\\]\\w\\[$(tput sgr0)\\]]\\\\$ \\[$(tput sgr0)\\]"' >> .bashrc

```

```jsx
for script in $(cat customization-scripts.txt); do curl -s <http://myvps.vps-provider.net/$script> | bash; done
#looping

```

## Windows

- Windows update

```powershell
Get-ExecutionPolicy -List
Set-ExecutionPolicy Unrestricted -Scope Process
# this applies to current powershell session only 
Install-Module PSWindowsUpdate
Import-Module PSWindowsUpdate
Install-WindowsUpdate -AcceptAll
Restart-Computer -Force

#some commands
RefreshEnv # update Powershell and any environment variables
```

- Windows Subsystem for Linux (WSL)
- Chocolatey Package Manager

```powershell
#installing chocolatey 
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco upgrade chocolatey -y

#installing package
choco install vscode
choco install microsoft-windows-terminal
choco install WSL2

```

- Windows Defender Exemptions for the Tools' Folders

```powershell
Add-MpPreference -ExclusionPath "C:\Users\your user here\AppData\Local\Temp\chocolatey\"Choco Build Script

C:\Users\your user here\AppData\Local\Temp\chocolatey\

C:\Users\your user here\Documents\git-repos\

C:\Users\your user here\Documents\scripts\
```

- Choco Build Script

```powershell
# Choco build script

write-host "*** Initial app install for core tools and packages. ***"

write-host "*** Configuring chocolatey ***"
choco feature enable -n allowGlobalConfirmation

write-host "*** Beginning install, go grab a coffee. ***"
choco upgrade wsl2 python git vscode openssh openvpn netcat nmap wireshark burp-suite-free-edition heidisql sysinternals putty golang neo4j-community openjdk

write-host "*** Build complete, restoring GlobalConfirmation policy. ***"
choco feature disable -n allowGlobalCOnfirmation
```

## VPS

- Providers
    - Vultr , digital ocean
- Note
    - VPS can be setup for IPv6
    - Many firewalls are only protected against IPv4 and IPv6 is forgotten
- SSH key generation

```powershell
ssh-keygen -t rsa -b 4096 -f vps-ssh
```

- Adding user to VPS

```powershell
adduser UserName
usermod -aG sudo UserName
```

- **Adding Public SSH Key to VPS**

```powershell
mkdir ~/.ssh
echo '<vps-ssh.pub>' > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

## VPS hardening

- Some ways
    - SSH hardening
        - /etc/ssh/sshd_config
    - Install Fail2ban
        - create backup of conf files
    - Working only with SSH keys
    - Reduce Idle timeout interval
    - Disable passwords
    - Disable x11 forwarding
    - Use a different port
    - Limit users' SSH access
    - Disable root logins
    - Use SSH proto 2
    - Enable 2FA Authentication for SSH
        - Google authenticator
        - [https://github.com/google/google-authenticator-libpam](https://github.com/google/google-authenticator-libpam)
        - Configure PAM Module (Pluggable Authentication Modules) for SSH daemon
            - /etc/pam.d/sshd
            
            ```powershell
            #@include common-auth
            auth required pam_google_authenticator.so
            auth required pam_permit.so
            ```
            
            - /etc/ssh/sshd_config
            
            ```powershell
            AuthenticationMethods publickey,keyboard-interactive
            PasswordAuthentication no
            ```
            
            - Restart SSH server
- SCP Syntax

```powershell
scp -i <ssh-private-key> -r <directory to transfer> <username>@<IP/FQDN>:<path>
```

-