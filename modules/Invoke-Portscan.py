# modules/Invoke-Portscan.py
import os
import importlib.util
import base64
import re

def get_info():
    """Get module information"""
    return {
        "name": "Invoke-Portscan",
        "description": "Execute a PowerShell Invoke-Portscan script to perform network port scanning",
        "type": "enumeration",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1046,T1059.001",  # Network Service Scanning, Command and Scripting Interpreter: PowerShell
        "mitre_tactics": ["Discovery"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run Invoke-Portscan on",
                "required": True
            },
            "computer_name": {
                "description": "Target computer name or IP address to scan (supports multiple targets separated by commas)",
                "required": True
            },
            "port": {
                "description": "Port or port range to scan (e.g., 80, 1-1000, 22,80,443)",
                "required": True
            },
            "ports": {
                "description": "Alternative parameter for specifying ports (for compatibility)",
                "required": False,
                "default": ""
            },
            "timeout": {
                "description": "Timeout in milliseconds for each connection attempt (default: 1000)",
                "required": False,
                "default": "1000"
            },
            "ping": {
                "description": "Perform ping sweep before port scanning (true/false) (default: false)",
                "required": False,
                "default": "false"
            },
            "all_protocols": {
                "description": "Include all protocols in the scan (true/false) (default: false)",
                "required": False,
                "default": "false"
            },

        }
    }


def execute(options, session):
    """Execute the Invoke-Portscan module with given options and session"""
    agent_id = options.get("agent_id")
    computer_name = options.get("computer_name")
    port = options.get("port")
    ports = options.get("ports", "")
    timeout = options.get("timeout", "1000")
    ping = options.get("ping", "false").lower()
    all_protocols = options.get("all_protocols", "false").lower()
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    if not computer_name:
        return {
            "success": False,
            "error": "computer_name is required"
        }
    
    if not port and not ports:
        return {
            "success": False,
            "error": "Either port or ports is required"
        }
    
    if ping not in ["true", "false"]:
        return {
            "success": False,
            "error": f"Invalid ping: {ping}. Must be 'true' or 'false'"
        }
    
    if all_protocols not in ["true", "false"]:
        return {
            "success": False,
            "error": f"Invalid all_protocols: {all_protocols}. Must be 'true' or 'false'"
        }
    
    # Validate timeout is numeric
    if not timeout.isdigit():
        return {
            "success": False,
            "error": f"Invalid timeout: {timeout}. Must be a numeric value."
        }
    
    # Validate computer_name for potential command injection
    # Only allow alphanumeric characters, dots, hyphens, commas, and common IP/CIDR patterns
    computer_name_pattern = r'^[a-zA-Z0-9.\-_\/,]+$'
    if not re.match(computer_name_pattern, computer_name.replace(' ', '')):
        return {
            "success": False,
            "error": f"Invalid computer_name format: {computer_name}. Contains invalid characters."
        }
    
    # Validate port for potential command injection  
    # Allow digits, commas, hyphens (for ranges), and asterisks
    port_pattern = r'^[0-9,*-]+$'
    if port and not re.match(port_pattern, port.replace(' ', '')):
        return {
            "success": False,
            "error": f"Invalid port format: {port}. Contains invalid characters."
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    

    
    # Read the original Invoke-Portscan.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Invoke-Portscan.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find Invoke-Portscan script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading Invoke-Portscan script: {str(e)}"
        }
    
    # Build the execution command with parameters based on provided options
    cmd_parts = ["Invoke-Portscan"]
    
    # Add computer name parameter
    cmd_parts.append(f"-ComputerName {computer_name}")
    
    # Add port parameter (prefer 'port' over 'ports' if both are provided)
    if port:
        cmd_parts.append(f"-Port {port}")
    elif ports:
        cmd_parts.append(f"-Ports {ports}")
    
    # Add timeout if different from default
    if timeout != "1000":
        cmd_parts.append(f"-Timeout {timeout}")
    
    # Add ping parameter if true
    if ping == "true":
        cmd_parts.append("-Ping")
    
    # Add all protocols parameter if true
    if all_protocols == "true":
        cmd_parts.append("-AllProtocols")
    
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
                "output": f"Invoke-Portscan task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "computer_name": computer_name,
                "port": port or ports,
                "timeout": timeout,
                "ping": ping,
                "all_protocols": all_protocols
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