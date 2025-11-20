# modules/PowerView.py
import os
import importlib.util
import base64
import re

def get_info():
    """Get module information"""
    return {
        "name": "PowerView",
        "description": "Execute a PowerShell PowerView script for network enumeration and domain assessment",
        "type": "enumeration",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1016,T1018,T1059.001,T1069,T1087,T1482,T1082",  # Various network reconnaissance techniques
        "mitre_tactics": ["Discovery"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run PowerView enumeration on",
                "required": True
            },
            "function": {
                "description": "The PowerView function to execute (default: 'Get-Domain'). Available functions include many for domain enumeration: Get-Domain, Get-DomainController, Get-DomainUser, Get-DomainGroup, Get-DomainComputer, Get-DomainGPO, Get-DomainOU, Get-DomainSite, Get-DomainSubnet, Get-DomainTrust, Get-Forest, Get-ForestDomain, Get-ForestGlobalCatalog, Find-DomainUserLocation, Find-DomainGroupMember, Find-DomainShare, Find-LocalAdminAccess, Get-NetSession, Get-NetLoggedon, Invoke-UserHunter, Invoke-ProcessHunter, Invoke-EventHunter, Invoke-ShareFinder, Invoke-FileFinder, Get-DNSServerZone, Get-DomainDNSRecord, Get-NetForestTrust, Get-ADObject, Get-NetGroupMember, Get-NetUser, Get-NetComputer, Get-NetDomainController, Get-NetGPO, Get-NetGPOGroup, Get-DFSshare, Get-NetShare, Get-NetLocalGroupMember, Find-ComputerField, Find-UserField, Get-NetDomainTrust, Get-NetForestTrust, Find-GPOLocation, Get-DomainPolicyData, Get-DomainUserEvent, Get-DomainProcess, Get-DomainUserPermission, Find-ManagedSecurityGroups, Get-DomainTrustMapping, Get-NetDomain",
                "required": False,
                "default": "Get-Domain"
            },
            "arguments": {
                "description": "Additional arguments to pass to the PowerView function (optional)",
                "required": False,
                "default": ""
            },

        }
    }


def execute(options, session):
    """Execute the PowerView module with given options and session"""
    agent_id = options.get("agent_id")
    function = options.get("function", "Get-Domain")
    arguments = options.get("arguments", "")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    allowed_functions = [
        "Get-Domain", "Get-DomainController", "Get-DomainUser", "Get-DomainGroup", 
        "Get-DomainComputer", "Get-DomainGPO", "Get-DomainOU", "Get-DomainSite", 
        "Get-DomainSubnet", "Get-DomainTrust", "Get-Forest", "Get-ForestDomain", 
        "Get-ForestGlobalCatalog", "Find-DomainUserLocation", "Find-DomainGroupMember", 
        "Find-DomainShare", "Find-LocalAdminAccess", "Get-NetSession", "Get-NetLoggedon", 
        "Invoke-UserHunter", "Invoke-ProcessHunter", "Invoke-EventHunter", "Invoke-ShareFinder", 
        "Invoke-FileFinder", "Get-DNSServerZone", "Get-DomainDNSRecord", "Get-NetForestTrust", 
        "Get-ADObject", "Get-NetGroupMember", "Get-NetUser", "Get-NetComputer", 
        "Get-NetDomainController", "Get-NetGPO", "Get-NetGPOGroup", "Get-DFSshare", 
        "Get-NetShare", "Get-NetLocalGroupMember", "Find-ComputerField", "Find-UserField", 
        "Get-NetDomainTrust", "Get-NetForestTrust", "Find-GPOLocation", "Get-DomainPolicyData", 
        "Get-DomainUserEvent", "Get-DomainProcess", "Get-DomainUserPermission", 
        "Find-ManagedSecurityGroups", "Get-DomainTrustMapping", "Get-NetDomain"
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
    

    
    # Read the original PowerView.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'PowerView.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find PowerView script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading PowerView script: {str(e)}"
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
                "output": f"PowerView task {task_id} queued for agent {agent_id}",
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