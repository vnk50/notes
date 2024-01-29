# 05_active_directory

## General

- Directory service, distributed, hierarchical , centralized management
- AD provides authentication and authorization functions within a Windows domain environment
- Backward compatible
- sizeable read-only database accessible to all users within the domain, regardless of their privilege level.
- A basic AD user account with no added privileges can enumerate most objects within AD
- noPac attack
- Conti Ransomware
- PrintNightmare Zerologon - CVE

## History

- LDAP -Lightweight Directory Access Protocol
- Kerberos?
- Active Directory Federation Services ADFS - uses the claims-based Access Control Authorization model
- Group Managed Service Accounts (gMSA) - recommended mitigation against the infamous Kerberoasting attack

## AD Structure

- A basic AD user can enumerate
    - Domain Computers; Domain Users; Domain Group Information; Organizational Units (OUs); Default Domain Policy; Functional Domain Levels; Password Policy; Group Policy Objects (GPOs); Domain Trusts; Access Control Lists (ACLs)
- Tree structure
    - Forest - security boundary within which all objects are under administrative control
    - Domain - contained objects (users,computers and groups)
        - Organizational Units (OUs) - Domain controllers, Users, Computers
    - Sub-domains
- Multiple domains/forests are linked together via trust relationships
- Trust between - INLANEFREIGHT.LOCAL and FREIGHTLOGISTICS.LOCAL
    - child domains in forest A do not necessarily have trusts established with the child domains in forest B
    - To allow direct communication from admin.dev.freightlogistics.local and wh.corp.inlanefreight.local, another trust would need to be set up.

![Untitled](images/05_active_directory/Untitled.png)

## AD Terminologies

- Object - any resource in AD
- Attributes - associated with objects
    - All attributes in AD have an associated LDAP name
- Schema - blueprint of any enterprise environment, defines what type of objects can exist
    - When an object is created from a class, this is called instantiation, and an object created from a specific class is called an instance of that class.
    - For example, if we take the computer RDS01. This computer object is an instance of the "computer" class in Active Directory.
- Domain - logical grouping of objects (independent or trust relationships)
- Forest - collection of AD domains; topmost container
- Tree - collection of AD domains that begins at a single root domain; forest is collection of AD tress
- Container - Container objects hold other objects and have a defined place in the directory subtree hierarchy
- Leaf
- Global Unique Identifier (GUID) - 128 bit value assigned when a domain user or group is created
    - every object GUID
    - store in `objectGUID` attribute
    - never changes
- Security principals - authentication ; domain objects that can manage access to other resources within the domain
    - We can also have local user accounts and security groups used to control access to resources on only that specific computer. These are not managed by AD but rather by the Security Accounts Manager (SAM).
- Security Identifier (SID) - unique identifier for a security principal or security group
    - issued by the domain controller
    - A SID can only be used once, even if security principle is deleted, it can never be used again in that environment to identify another user or group.
- Distinguished Name (DN) - describes the full path to an object in AD
- Relative DN
- sAMAccountName - user’s logon name
- userPrincipalName
- FSMO Roles - Flexible Singel Master Operation (FSMO) roles
    - Schema Master
    - Domain Naming Master (one per forest)
    - Relative ID (RID) Master (one per domain)
    - Primary Domain Controller (PDC) Emulator (one per domain)
    - Infrastructure Master (one per domain)
- Global catalog (GC)
    - domain controller that store copies of ALL object in AD forest
- Read-Only Domain Controller (RODC)
- Replication - happens in AD when AD objects are updated and transferred from one Domain Controller to another
- Service Principal Name (SPN) - used by Keberos authentication
- Group Policy Object (GPO) - virtual collections of policy settings
- Access Control List (ACL) - ordered collection of Access Control Entries (ACEs)
- Access Control Entries (ACE)
- Discretionary Access Control List (DACL) - define which security principles are granted or denied access to an object; contains list of ACEs
- System Access Control Lists (SACL)
- Fully Qualified Domain Name (FQDN) - [host name].[domain name].[tld]
- Tombstone - container object in AD that holds deleted AD objects
- AD Recycle Bin - deleted objects attributes are preserved
- SYSVOL - folder
- AdminSDHolder - object is used to manage ACLs for members of built-in groups in AD marked as privileged
    - The SDProp (SD Propagator) process runs on a schedule on the PDC Emulator Domain Controller. When this process runs, it checks members of protected groups to ensure that the correct ACL is applied to them. It runs every hour by default.
- dsHeuristics
    - The dsHeuristics attribute is a string value set on the Directory Service object used to define multiple forest-wide configuration settings. One of these settings is to exclude built-in groups from the Protected Groups list. Groups in this list are protected from modification via the `AdminSDHolder` object. If a group is excluded via the dsHeuristics attribute, then any changes that affect it will not be reverted when the SDProp process runs.
- adminCount
    - 0 not protected
    - set - user is protected
- Active Directory Users and Computers (ADUC).
- ADSI Edit
- sIDHistory
- NTDS.DIT
    - stored on a Domain Controller at C:\Windows\NTDS\
    - database that stores AD data such as information about user and group objects, group membership
    - contains hashes of passwords of all users in a domain
- MSBROWSE - Microsoft networking protocol (old)

## AD Objects

- Object can be any resource present within AD such as OUs, printers, users, domain controllers
- Users
    - leaf objects
    - A user object is considered a security principal and has a security identifier (SID) and a global unique identifier (GUID)
- Contacts
    - leaf objects , not security principals (no SID), only GUID
- Printers
- Computers
    - leaf object
    - SID GUID
- Shared folders
    - GUID
- Groups
    - container object
    - SID GUID
- Organizational Units (OUs)
    - a container that systems administrators can use to store similar objects for ease of administration
- Domain
    - Every domain has its own separate database and sets of policies that can be applied to any and all objects within the domain.
- Domain Controllers
    - They handle authentication requests, verify users on the network, and control who can access the various resources in the domain. All access requests are validated via the domain controller and privileged access requests are based on predetermined roles assigned to users. It also enforces security policies and stores information about every other object in the domain.
- Sites - set of computer across one or more subnets
- Built-in - container that holds default groups in AD domain
- Foreign Security Principals - object created in AD to represent a security principal that belongs to a trusted external forest.

## AD Functionality

- There are five Flexible Single Master Operation roles
- Schema Master - This role manages the read/write copy of the AD schema, which defines all attributes that can apply to an object in AD.
- Domain Naming Master - Manages domain names and ensures that two domains of the same name are not created in the same forest.
- Relative ID (RID) Master	- The RID Master assigns blocks of RIDs to other DCs within the domain that can be used for new objects. The RID Master helps ensure that multiple objects are not assigned the same SID. Domain object SIDs are the domain SID combined with the RID number assigned to the object to make the unique SID.
- PDC Emulator	- The host with this role would be the authoritative DC in the domain and respond to authentication requests, password changes, and manage Group Policy Objects (GPOs). The PDC Emulator also maintains time within the domain.
- Infrastructure Master - This role translates GUIDs, SIDs, and DNS between domains. This role is used in organizations with multiple domains in a single forest. The Infrastructure Master helps them to communicate. If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names.

## Trusts

- A trust is used to establish forest-forest or domain-domain authentication
- Parent-child
- Cross-link
- External
- Tree-root
- Forest
- A transitive trust means that trust is extended to objects that the child domain trusts.
- In a non-transitive trust, only the child domain itself is trusted.
- Trusts can be set up to be one-way or two-way (bidirectional).
    - In bidirectional trusts, users from both trusting domains can access resources.
    - In a one-way trust, only users in a trusted domain can access resources in a trusting domain, not vice-versa. The direction of trust is opposite to the direction of access.

## Protocols

- Active Directory specifically requires Lightweight Directory Access Protocol (LDAP), Microsoft's version of Kerberos, DNS for authentication and communication,
- MSRPC which is the Microsoft implementation of Remote Procedure Call (RPC), an interprocess communication technique useLightweight Directory Access Protocol (LDAP) for directory lookupsd for client-server model-based applications.

### Kerberos

- default authentication protocol for domain accounts since Windows 2000
- When a user logs into their PC, Kerberos is used to authenticate them via mutual authentication, or both the user and the server verify their identity
- stateless authentication protocol based on tickets instead of transmitting user passwords over the network.
- As part of Active Directory Domain Services (AD DS), Domain Controllers have a Kerberos Key Distribution Center (KDC) that issues tickets
- Port 88 (TCP and UDP)
- Kerberos Authentication Process
    1. The user logs on, and their password is converted to an NTLM hash, which is used to encrypt the TGT ticket. This decouples the user's credentials from requests to resources.
    2. The KDC service on the DC checks the authentication service request (AS-REQ), verifies the user information, and creates a Ticket Granting Ticket (TGT), which is delivered to the user.
    3. The user presents the TGT to the DC, requesting a Ticket Granting Service (TGS) ticket for a specific service. This is the TGS-REQ. If the TGT is successfully validated, its data is copied to create a TGS ticket.
    4. The TGS is encrypted with the NTLM password hash of the service or computer account in whose context the service instance is running and is delivered to the user in the TGS_REP.
    5. The user presents the TGS to the service, and if it is valid, the user is permitted to connect to the resource (AP_REQ).
    
    ![Untitled](images/05_active_directory/Untitled%201.png)
    
    ### DNS
    
    - AD DS uses DNS , users - locate - domain controllers
    - AD maintains a database of services running on the network in the form of service records (SRV).
    - DNS uses TCP and UDP port 53. UDP port 53 is the default, but it falls back to TCP when no longer able to communicate and DNS messages are larger than 512 bytes.
    
    ![Untitled](images/05_active_directory/Untitled%202.png)
    
- Forward DNS Lookup - `nslookup name`
- Reverse DNS Lookup - `nslookup ip`

### LDAP

- Lightweight Directory Access Protocol (LDAP) for directory lookups
- Port - 389
- LDAP ove SSL  port - 636
- LDAP is how systems in the network environment can "speak" to AD.
- An LDAP session begins by first connecting to an LDAP server, also known as a Directory System Agent. The Domain Controller in AD actively listens for LDAP requests, such as security authentication requests.

![Untitled](images/05_active_directory/Untitled%203.png)

- AD LDAP Authentication
    - LDAP is set up to authenticate credentials against AD using a "BIND" operation to set the authentication state for an LDAP session. There are two types of LDAP authentication.
    - Simple Authentication - username and password used to create a BIND request to authenticate to the LDAP server
    - SASL Authentication - Simple Authentication and Security Layer
- LDAP authentication messages are sent in cleartext by default so anyone can sniff out LDAP messages on the internal network. It is recommended to use TLS encryption or similar to safeguard this information in transit.

### MSRPC

- Microsoft's implementation of Remote Procedure Call (RPC), an interprocess communication technique used for client-server model-based applications.
- Windows systems use MSRPC to access systems in Active Directory using four key RPC interfaces
    - lsarpc
    - netlogon
    - samr
    - drsuapi

## NTLM Authentication

- LM NTLN - Hash names
- NTLMv1 and NTLMv2 - authentication protocols
- NT LAN Manager (NTLM) hashes
    - challenge response

![Untitled](images/05_active_directory/Untitled%204.png)

```markdown
Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::

Rachel - username
500 - Realtive ID ( administrator) 
aad3c435b514a4eeaad3b935b51304fe is the LM hash
e46b9e548fa0d122de7f59fb6d48eaa2 is the NT hash

```

- Domain Cached Credentials (MSCache2)
    - Hosts save the last ten hashes for any domain users that successfully log into the machine in the HKEY_LOCAL_MACHINE\SECURITY\Cache registry key

## User and machine accounts

- User accounts present an immense attack surface and are usually a key focus for gaining a foothold during a penetration test.
- Local accounts
    - Administrator - SID S-1-5-domain-500
    - Guest
    - SYSTEM or NT AUTHORITY\SYSTEM - profile doesn’t exist and does not appear in user manager and cannot be added to any groups
    - Network Service
    - Local Service
- Domain Users
    - KRBTGT account - account acts as a service account for the Key Distribution service providing authentication and access for domain resources
- User Naming Attributes
    - UserPrinicipalName ObjectGUID SAMAccountName pbjectSID sIDHistory
    - Common user attributes `Get-ADUser -Identity name`
- Domain-joined vs. Non-Domain-joined Machines

## AD Groups

- OUs are useful for grouping users, groups, and computers to ease management and deploying Group Policy settings to specific objects in the domain. Groups are primarily used to assign permissions to access resources. OUs can also be used to delegate administrative tasks to a user, such as resetting passwords or unlocking user accounts without giving them additional admin rights that they may inherit through group membership.
- Groups
    - type
        - security
        - distribution
    - scope
        - domain local
        - global
        - universal
            - stored in the Global Catalog (GC)
- `Get-ADGroup -Filter * |select samaccountname,groupscope`
- Built-in groups do not allow nesting
- Tool - BloodHount
- Important Group Attributes
    - cn - Common-Name
    - member
    - groupType
    - memberOf
    - objectSid

## AD Rights and Privileges

- Rights are typically assigned to users or groups and deal with permissions to access an object such as a file,
- Pprivileges grant a user permission to perform an action such as run a program, shut down a system, reset passwords, etc
- Common Built-in groups
    - Account Operators
    - Administrators
    - Backup Operators
    - DnsAdmins
    - Domain Admins
    - Domain Computers
    - Domain Controllers
    - Domain Guests
    - Domain Users
    - **Enterprise Admins**
    - Event Log Readers
    - Group Policy Creator Owners
    - Hyper-V Administrators
    - IIS_IUSRS
    - Pre-Windows 2000 Compatible Access
    - Print Operators
    - Protected Users
    - Read-only Domain Controllers
    - Remote Desktop Users
    - Remote Management Users
    - **Schema Admins**
    - Server Operators
- `Get-ADGroup -Identity "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members`
- `Get-ADGroup -Identity "Server Operators" -Properties *`

```markdown
PS C:\htb>  Get-ADGroup -Identity "Server Operators" -Properties *

adminCount                      : 1
CanonicalName                   : INLANEFREIGHT.LOCAL/Builtin/Server Operators
CN                              : Server Operators
Created                         : 10/27/2021 8:14:34 AM
createTimeStamp                 : 10/27/2021 8:14:34 AM
Deleted                         : 
Description                     : Members can administer domain servers
DisplayName                     : 
DistinguishedName               : CN=Server Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL
dSCorePropagationData           : {10/28/2021 1:47:52 PM, 10/28/2021 1:44:12 PM, 10/28/2021 1:44:11 PM, 10/27/2021 
                                  8:50:25 AM...}
GroupCategory                   : Security
GroupScope                      : DomainLocal
groupType                       : -2147483643
HomePage                        : 
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       : 
LastKnownParent                 : 
ManagedBy                       : 
MemberOf                        : {}
Members                         : {}
Modified                        : 10/28/2021 1:47:52 PM
modifyTimeStamp                 : 10/28/2021 1:47:52 PM
Name                            : Server Operators
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
ObjectClass                     : group
ObjectGUID                      : 0887487b-7b07-4d85-82aa-40d25526ec17
objectSid                       : S-1-5-32-549
ProtectedFromAccidentalDeletion : False
SamAccountName                  : Server Operators
sAMAccountType                  : 536870912
sDRightsEffective               : 0
SID                             : S-1-5-32-549
SIDHistory                      : {}
systemFlags                     : -1946157056
uSNChanged                      : 228556
uSNCreated                      : 12360
whenChanged                     : 10/28/2021 1:47:52 PM
whenCreated                     : 10/27/2021 8:14:34 AM
```

- User Rights Management
    - SeRemoteInteractiveLogonRight
    - SeBackupPrivilege
    - SeDebugPrivilege
    - SeImpersonatePrivilege
    - SeLoadDriverPrivilege
    - SeTakeOwnershipPrivilege
- Viewing a User's Privileges
    - `whoami /priv`
- Rights are restricted by User Account Control (UAC)

## Security in Active Directory

![Untitled](images/05_active_directory/Untitled%205.png)

- The Microsoft Local Administrator Password Solution (LAPS) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.
- Audit Policy Settings (Logging and Monitoring)
- Group Policy Security Settings
- Advanced Audit Policy
- Update Management (SCCM/WSUS)
- Group Managed Service Accounts (gMSA)
- Security Groups
- Account Separation
- Password Complexity Policies + Passphrases + 2FA
- Limiting Domain Admin Account Usage
- Periodically Auditing and Removing Stale Users and Objects
- Auditing Permissions and Access
- Audit Policies & Logging
- Using Restricted Groups
- Limiting Server Roles
- Limiting Local Admin and RDP Rights

## Examining Group Policy

- Group Policy Objects (GPOs)
    - virtual collection of policy settings that can be applied to user(s) or computer(s).
    - GPOs are processed from the top down when viewing them from a domain organizational standpoint
- GPO Precedence Order ???
- Group Policy Refresh Frequency
