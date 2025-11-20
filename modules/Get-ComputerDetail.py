import os
import importlib.util
import base64
import re

def get_info():
    """Get module information"""
    return {
        "name": "Get-ComputerDetail",
        "description": "Execute a PowerShell Get-ComputerDetail script to gather comprehensive system information",
        "type": "enumeration",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1082,T1016,T1033,T1057,T1005,T1059.001",  # System Information Discovery, System Network Configuration Discovery, User Discovery, Process Discovery, Data from Local System, Command and Scripting Interpreter: PowerShell
        "mitre_tactics": ["Discovery"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run Get-ComputerDetail on",
                "required": True
            },
            "computer_name": {
                "description": "Target computer name or IP address to enumerate (default: localhost)",
                "required": False,
                "default": ""
            },
            "credentialed_access": {
                "description": "Use alternate credentials for remote enumeration (format: domain\\username:password)",
                "required": False,
                "default": ""
            },
            "property": {
                "description": "Specific property to retrieve (optional, if not specified, all properties will be returned)",
                "required": False,
                "default": ""
            },

        }
    }


def execute(options, session):
    """Execute the Get-ComputerDetail module with given options and session"""
    agent_id = options.get("agent_id")
    computer_name = options.get("computer_name", "")
    credentialed_access = options.get("credentialed_access", "")
    property_val = options.get("property", "")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    if computer_name:
        computer_name_pattern = r'^[a-zA-Z0-9.\-_\/]+$'
        if not re.match(computer_name_pattern, computer_name):
            return {
                "success": False,
                "error": f"Invalid computer_name format: {computer_name}. Contains invalid characters."
            }

    if property_val:
        property_pattern = r'^[a-zA-Z0-9_-]+$'
        if not re.match(property_pattern, property_val):
            return {
                "success": False,
                "error": f"Invalid property format: {property_val}. Contains invalid characters."
            }

    if credentialed_access:
        cred_pattern = r'^[a-zA-Z0-9_-]+\\[a-zA-Z0-9_-]+:[^:]+$'
        if not re.match(cred_pattern, credentialed_access):
            return {
                "success": False,
                "error": f"Invalid credentialed_access format: {credentialed_access}. Must be in format domain\\username:password."
            }

    session.current_agent = agent_id



    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Get-ComputerDetail.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find Get-ComputerDetail script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading Get-ComputerDetail script: {str(e)}"
        }
    
    # Build the execution command with parameters based on provided options
    cmd_parts = ["Get-ComputerDetail"]
    
    # Add computer name parameter if provided
    if computer_name:
        cmd_parts.append(f"-ComputerName {computer_name}")
    
    # Add credential parameter if provided
    if credentialed_access:
        domain_user, password = credentialed_access.split(':', 1)
        domain, username = domain_user.split('\\', 1)
        # Note: In a real scenario, credentials would be handled more securely
        cmd_parts.append(f"-Credential (New-Object System.Management.Automation.PSCredential('{domain}\\{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force)))")
    
    # Add property parameter if provided
    if property_val:
        cmd_parts.append(f"-Property {property_val}")
    
    # Combine into command
    command_str = " ".join(cmd_parts)
    execution_command = f"{original_script}\n{command_str}"
    
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
                "output": f"Get-ComputerDetail task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "computer_name": computer_name,
                "property": property_val
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