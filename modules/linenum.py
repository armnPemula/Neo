# modules/linenum.py
import os
import re
import base64


def get_info():
    return {
        "name": "linenum",
        "description": "Execute LinEnum.sh script for comprehensive Linux system enumeration and reconnaissance",
        "type": "reconnaissance",
        "platform": "linux",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/rebootuser/LinEnum"],
        "technique_id": "T1033,T1016,T1049,T1082,T1087,T1083,T1542,T1069,T1147,T1124,T1057,T1592,T1566,T1589,T1590,T1080,T1538,T1622",  # System Owner/User Discovery, System Network Configuration Discovery, System Network Connections Discovery, System Information Discovery, Account Discovery, File and Directory Discovery, System Services, Permission Groups Discovery, Hidden Files and Directories, System Time Discovery, Process Discovery, Gather Victim Host Information, Phishing for Information, Gather Victim Identity Information, Gather Victim Network Information, Taint Shared Content, Cloud Service Dashboard, Debugger Evasion
        "mitre_tactics": ["Discovery", "Privilege Escalation", "Collection"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run LinEnum on",
                "required": True
            },
            "keyword": {
                "description": "Keyword to search for in config, php, ini and log files",
                "required": False,
                "default": ""
            },
            "report_name": {
                "description": "Name of the report file to generate",
                "required": False,
                "default": ""
            },
            "export_location": {
                "description": "Location to export collected files (default: /tmp)",
                "required": False,
                "default": "/tmp"
            },
            "thorough": {
                "description": "Include thorough (lengthy) tests",
                "required": False,
                "default": False
            },
            "sudo_password": {
                "description": "Supply user password for sudo checks (INSECURE - for CTF use only)",
                "required": False,
                "default": ""
            }
        }
    }


def execute(options, session):
    agent_id = options.get("agent_id")
    keyword = options.get("keyword", "")
    report_name = options.get("report_name", "")
    export_location = options.get("export_location", "/tmp")
    thorough = options.get("thorough", False)
    sudo_password = options.get("sudo_password", "")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    # Validate inputs
    if keyword and not re.match(r'^[a-zA-Z0-9_\-\.]+$', keyword):
        return {
            "success": False,
            "error": f"Invalid keyword: {keyword}. Contains invalid characters."
        }
    
    if report_name and not re.match(r'^[a-zA-Z0-9_\-\.]+$', report_name):
        return {
            "success": False,
            "error": f"Invalid report_name: {report_name}. Contains invalid characters."
        }
    
    if not re.match(r'^[a-zA-Z0-9_\-\/\.~]+$', export_location):
        return {
            "success": False,
            "error": f"Invalid export_location: {export_location}. Contains invalid characters."
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    
    # Build the LinEnum command based on options
    try:
        # Create a temporary location for the script
        temp_script_path = f"{export_location}/LinEnum.sh"
        
        # LinEnum script content (from the existing file in modules/linux/)
        linenum_script_path = os.path.join(os.path.dirname(__file__), 'linux', 'LinEnum.sh')
        try:
            with open(linenum_script_path, 'r', encoding='utf-8') as f:
                linenum_script_content = f.read()
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Could not find LinEnum script at {linenum_script_path}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error reading LinEnum script: {str(e)}"
            }
        
        # Encode the script content in base64 to transfer it
        script_b64 = base64.b64encode(linenum_script_content.encode()).decode()
        
        # Build command to transfer and execute the script
        linenum_cmd = f"echo '{script_b64}' | base64 -d > {temp_script_path} && chmod +x {temp_script_path} && "
        
        # Build the LinEnum execution command with parameters
        linenum_exec = f"bash {temp_script_path}"
        
        if keyword:
            linenum_exec += f" -k {keyword}"
        
        if report_name:
            linenum_exec += f" -r {report_name}"
        else:
            # Use a default report name with timestamp
            import time
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            linenum_exec += f" -r LinEnum_report_{timestamp}"
        
        if export_location:
            linenum_exec += f" -e {export_location}"
        
        if thorough:
            linenum_exec += " -t"
        
        if sudo_password:
            # The -s flag in LinEnum is for supplying user password for sudo checks (INSECURE)
            linenum_exec += " -s"
        
        linenum_cmd += f"{linenum_exec}"
        
        # Add cleanup command to remove the temporary script (without breaking the output piping)
        # We need to execute the script first and capture its output, then cleanup
        linenum_cmd += f" ; rm {temp_script_path}"
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Error building LinEnum command: {str(e)}"
        }
    
    # Check if session has a valid agent_manager
    if not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }
    
    # Queue the task on the agent
    try:
        agent_manager = session.agent_manager
        task_id = agent_manager.add_task(agent_id, linenum_cmd)
        if task_id:
            result = {
                "success": True,
                "output": f"LinEnum task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "options_used": {
                    "keyword": keyword if keyword else "None",
                    "report_name": report_name if report_name else "Default with timestamp",
                    "export_location": export_location,
                    "thorough": "Enabled" if thorough else "Disabled",
                    "sudo_password": "Provided (INSECURE)" if sudo_password else "Not provided"
                }
            }
            
            # Add additional info about where to find results if a report was requested
            if report_name:
                result["output"] += f"\nReport will be saved as {export_location}/{report_name}-DD-MM-YY (actual filename will include date)"
            
            return result
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
