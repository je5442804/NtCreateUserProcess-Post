# NtCreateUserProcess-Post && NtCreateUserProcess-Native
NtCreateUserProcess with CsrClientCallServer for mainstream Windows x64 version.  

Reimplement this: __NtCreateUserProcess->BasepConstructSxsCreateProcessMessage->  
->CsrCaptureMessageMultiUnicodeStringsInPlace->CsrClientCallServer__  

__This project could be useless, however it's also useful to learn!__  
  
I'll try to fix some known bugs, Any questions,suggestions and pulls are welcomed __:)__  
__I will mainly try to support ALL Windows x64 verison from win 7 to win 11.__  

NtCreateUserProcess-Native support Standard IO Redirect.  
NtCreateUserProcess-Native is the Native Edition which remove BasepConstructSxsCreateProcessMessage, RtlCreateProcessParametersEx,   CsrCaptureMessageMultiUnicodeStringsInPlace...  just prevent any function hook?  

NtCreateUserProcess-Native is created for OPSEC, RedTeam purpose.  
__I have enabled CFG in NtCreateUserProcess-Native Project Settings.__  

__There is no plan to support AppX Package in this project.__  
<del>__I have nearly finished Reverse Engineering of CreateProcessInternalW of Windows 21H*,__</del>  
<del>__but a few improvement,struct, data type... required, I need more time...__</del>  
__Try [CreateProcessInternalW-Full](https://github.com/je5442804/CreateProcessInternalW-Full) instead__  
Hope the later CreateProcessInternalW project will help you gain different knowledge and understanding,  
which reimplement to support AppX, 16 bit RaiseError, .bat && .cmd File.   

## Reverse Engineering
After the release of [Direct-NtCreateUserProcess](https://github.com/D0pam1ne705/Direct-NtCreateUserProcess) and article by D0pam1ne705,  
I think I should also share my the Reverse Engineering results of CreateProcessInternalW (there's no need to keep it private).  
Different from his reverse route, I didn't kernel debug ALPC and csrss.exe,  
but mainly depends on IDA and memory analysis parameter.

## Example
 __NtCreateUserProcess-Post.exe  (ImagePath)__  
 (NtCreateUserProcess-Post Temporarily Deprecated??? I'm lazy...ovO)  
(Default is C:\Windows\System32\dfrgui.exe without special ImagePath)  
(1) NtCreateUserProcess-Post.exe  
(2) NtCreateUserProcess-Post.exe C:\Windows\System32\notepad.exe  
(3) NtCreateUserProcess-Post.exe C:\Windows\System32\taskmgr.exe  
(4) NtCreateUserProcess-Post.exe "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"   
 and so on...  
 C:\Windows\System32\DisplaySwitch.exe  
"C:\Program Files\Google\Chrome\Application\chrome.exe"  
 C:\Windows\System32\Magnify.exe  
......

__NtCreateUserProcess-Native.exe &nbsp; &nbsp;(-c ImagePath) &nbsp; &nbsp;(-i InteractType)__  
__(Standard File IO redirect is already supportd in NtCreateUserProcess-Native!)__  

-i 0: (Default) None of any interact mode will be used, like CREATE_NEW_CONSOLE  
-i 1: StdHandle via AttributeList, like bInheritHandles = FALSE  
-i 2: Set ProcessParameters Std Input,Output,OutError with CurrentProcessParameters Value, like bInheritHandles = TRUE  

(Default is C:\Windows\System32\dfrgui.exe without special Argument)  
(1) NtCreateUserProcess-Native.exe  
(2) NtCreateUserProcess-Native.exe -c C:\Windows\system32\cmd.exe -i 1  
(3) NtCreateUserProcess-Native.exe -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -i 2  
(4) NtCreateUserProcess-Native.exe -c "C:\Program Files\Google\Chrome\Application\chrome.exe" -i 0  
......

## My Build Environment
Visual Studio 2022 (Visual Studio 2019 should work)  
__Relase x64__

## BasepConstructSxsCreateProcessMessage???
Well, if you think this one is complex and redundant,
Try the Native Edition [__NtCreateUserProcess-Native__](https://github.com/je5442804/NtCreateUserProcess-Post/tree/main/NtCreateUserProcess-Native)  

## Tested on (x64 Only):  
 __Notice: On Windows 11 notepad.exe is AppX so it doesn't work__  
 Windows 11 23H2 Insider x64 (26020.1000)  
 Windows 11 21H2 x64 (22000.613)  
 Windows 10 21H2 x64 (19044.1706)  
 Windows 10 21H1 x64 (19043.1023)  
 Windows 10 2004 x64 (19041.264)  
 Windows 10 1909 x64 (18363.2274)  
 Windows Server 2019 x64 (17763.107)  
 Windows 10 1709 x64 (16299.125)  
 Windows 10 1703 x64 (15063.2078)  
 Windows Server 2016 x64 (14393.5066)  
 Windows 10 1607 x64 (14393.447)  
 Windows 10 1511 x64 (10586.164)  
 Windows 10 1507 x64 (10240)  
 Windows Server 2012 R2 x64 (9600)  
 Windows Server 2012 x64 (9200)  
 Windows Server 2008 R2 x64 (7601)  
 Windows 7 SP1 x64 (7601)  
 Windows Server 2008 R2 x64 (7600）  
 Windows Server 2008 x64 (6002）  
 Windows Vista SP2 x64 (6002)  
 Windows Vista x64 (6000)  

 
## References && Credits

1: https://github.com/Microwave89/createuserprocess  
2: https://github.com/PorLaCola25/PPID-Spoofing  
3: https://github.com/processhacker/processhacker  
4: https://www.geoffchappell.com/studies/windows/win32/csrsrv/api/apireqst/api_msg.htm  
5: https://github.com/leecher1337/ntvdmx64  
6: https://github.com/klezVirus/SysWhispers3  
7: https://bbs.pediy.com/thread-207429.htm  
8: https://doxygen.reactos.org  
9: https://github.com/waleedassar/NativeDebugger  
10: https://stackoverflow.com/questions/69599435/running-programs-using-rtlcreateuserprocess-only-works-occasionally  
11: https://medium.com/philip-tsukerman/activation-contexts-a-love-story-5f57f82bccd  
12: https://github.com/ShashankKumarSaxena/nt5src  
13: https://github.com/D4stiny/spectre  
14: https://github.com/x64dbg/TitanEngine  
15: https://github.com/x64dbg/ScyllaHide  
16: https://github.com/deroko/activationcontext  
17: https://medium.com/philip-tsukerman/activation-contexts-a-love-story-5f57f82bccd  
18: https://wasm.in/threads/csrclientcallserver-v-windows-7.29743/  
19: https://bbs.csdn.net/topics/360229611  
20: https://www.exploit-db.com/exploits/46712  
11: https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2020/CVE-2020-1027.html  
22: https://ii4gsp.tistory.com/288  
23: https://www.unknowncheats.me/forum/c-and-c-/121045-ntdll-module-callback.html  
