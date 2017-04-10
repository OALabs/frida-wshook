# frida-wshook
 
frida-wshook is an analysis and instrumentation tool which uses [frida.re](https://www.frida.re/) to hook common functions 
often used by malicious script files which are run using [WScript](https://technet.microsoft.com/en-us/library/hh875526(v=ws.11).aspx)/[CScript](https://technet.microsoft.com/en-us/library/bb490887.aspx).

As the tool intercepts Windows API functions it supports analyzing both .js ([JScript](https://en.wikipedia.org/wiki/JScript)) & .vbs ([VBScript](https://en.wikipedia.org/wiki/VBScript)) 
scripts and doesn't need to implement function stubs or proxies within the targeted scripting language. 

By default script files are run using cscript.exe and will output:

 - COM ProjIds 
 - DNS Requests 
 - Shell Commands
 - Network Requests
 
 __Warning!!! Ensure that you run any malicious scripts on a dedicated analysis system.__ Ideally, a VM with snapshots 
 so you can revert if a script gets away from you and you need to reset the system. 
 
 Although common methods have been hooked, Windows provides numerous APIs which allow developers to interact with a network, 
 file system and execute commands. So it is entirely possible to encounter scripts leveraging uncommon APIs for these functions. 
   
## Install & Setup 
 
 - Install [Python 2.7](https://www.python.org/downloads/windows/)
 - Install the [Frida](https://pypi.python.org/pypi/frida) python bindings using pip 
```
pip install frida
```
 - Clone (or download) the frida-wshook repository.

### Supported OS 

frida-wshook has been tested on Windows 10 and Windows 7 and _should_ work on any Windows 7 + environment. On x64 systems
 CScript is loaded from the C:\Windows\SysWow64 directory.
 
It _may_ work on WindowsXP, but I suspect that CScript may use the legacy API calls and would bypass the instrumentation.

## Usage 
The script supports a number of optional commandline arguments that allow you to control what APIs the scripting host 
can call.  
```
usage: frida-wshook.py [-h] [--debug] [--disable_dns] [--disable_com_init]
                       [--enable_shell] [--disable_net]
                       script

frida-wshook.py your friendly WSH Hooker

positional arguments:
  script              Path to target .js/.vbs file

optional arguments:
  -h, --help          show this help message and exit
  --debug             Output debug info
  --disable_dns       Disable DNS Requests
  --disable_com_init  Disable COM Object Id Lookup
  --enable_shell      Enable Shell Commands
  --disable_net       Disable Network Requests
```

Analyze a script with the default parameters:

```
python wshook.py bad.js
```

Enable verbose debugging:
```
python wshook.py --debug bad.js
```

Enable shell (execute) commands:
```
python frida-wshook.py --enable_shell bad.vbs
```

Disable WSASend:
```
python frida-wshook.py --disable_net bad.vbs
```

Check what ProgIds the script uses: 
```
python frida-wshook.py --disable_com_init bad.vbs
```

## Hooked Functions 

 - ole32.dll 
   - [CLSIDFromProgIDEx](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680113(v=vs.85).aspx) 
 - Shell32.dll
   - [ShellExecuteEx](https://msdn.microsoft.com/en-us/library/windows/desktop/bb762154(v=vs.85).aspx) 
 - Ws2_32.dll
   - [WSASocketW](https://msdn.microsoft.com/en-us/library/windows/desktop/ms742212(v=vs.85).aspx)
   - [GetAddrInfoExW](https://msdn.microsoft.com/en-us/library/windows/desktop/ms738518(v=vs.85).aspx)
   - [WSASend](https://msdn.microsoft.com/en-us/library/windows/desktop/ms742203(v=vs.85).aspx) 
   - [WSAStartup](https://msdn.microsoft.com/en-us/library/windows/desktop/ms742213(v=vs.85).aspx)

## Known Issues 

 - Passing an unsupported script extension will cause cscript to throw an import error and silently quit. Ensure that the target
script uses either .js or .vbs as the extension.
```
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

Input Error: There is no script engine for file extension ".bad".

```
 - Network responses are not captured
 - Disabling Object Lookup can cause the script to only output the first ProgId...Malware QA can be lacking. 

## TODO
 
  - Change GetAddrInfoExW to use .replace instead of .attach
  - Add additional tracing and hooks to cover more APIs
  - Look at bypassing common anti-analysis techniques found in scripts (sleeps etc)
  - Update and improve network request hooking (ie: currently it captures requests, but not responses)
  
## Feedback / Help 

Any questions, comments or requests you can find us on twitter: [@seanmw](https://twitter.com/herrcore) or [@herrcore](https://twitter.com/herrcore)


 