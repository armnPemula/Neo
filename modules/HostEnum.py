# modules/HostEnum.py
import os
import json
import base64
import re

def get_info():
    """Get module information"""
    return {
        "name": "HostEnum",
        "description": "Execute a PowerShell HostEnum script for comprehensive host enumeration and situational awareness",
        "type": "recon",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1082,T1016,T1033,T1057,T1005,T1083,T1566",  # System Information Discovery, System Network Configuration Discovery, Account Discovery, Process Discovery, Data from Local System, File and Directory Discovery, Phishing
        "mitre_tactics": ["Discovery", "Collection"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run HostEnum enumeration on",
                "required": True
            },
            "switch": {
                "description": "The HostEnum switch to execute. Available switches: All, Local, Domain, Privesc, Quick. Default: Local",
                "required": False,
                "default": "Local"
            },
            "html_report": {
                "description": "Generate an HTML report (true/false). Default: false",
                "required": False,
                "default": "false"
            }
        }
    }

def execute(options, session):
    """Execute the HostEnum module with given options and session"""
    agent_id = options.get("agent_id")
    switch = options.get("switch", "Local")
    html_report = options.get("html_report", "false")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    allowed_switches = ["All", "Local", "Domain", "Privesc", "Quick"]
    
    if switch not in allowed_switches:
        return {
            "success": False,
            "error": f"Invalid switch: {switch}. Must be one of: {', '.join(allowed_switches)}"
        }
    
    # Validate html_report parameter
    if html_report.lower() not in ["true", "false"]:
        return {
            "success": False,
            "error": f"html_report must be 'true' or 'false', got: {html_report}"
        }
    
    html_report_bool = html_report.lower() == "true"
    
    # Set the current agent in the session
    session.current_agent = agent_id
    
    # Read the HostEnum.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'HostEnum.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find HostEnum script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading HostEnum script: {str(e)}"
        }
    
    # Build the execution command with parameters based on the switch
    if html_report_bool:
        execution_command = f"{original_script}\nInvoke-HostEnum -{switch} -HTMLReport"
    else:
        execution_command = f"{original_script}\nInvoke-HostEnum -{switch}"
    
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
                "output": f"HostEnum task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "switch": switch,
                "html_report": html_report_bool
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