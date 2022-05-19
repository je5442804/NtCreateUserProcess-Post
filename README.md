# NtCreateUserProcess-Post
NtCreateUserProcess with CsrClientCallServer for mainstream Windows x64 version.  

Reimplement this: NtCreateUserProcess->BasepConstructSxsCreateProcessMessage->  
->CsrCaptureMessageMultiUnicodeStringsInPlace->CsrClientCallServer

This project could be useless, however it's also useful to learn!  

I'll try to fix some known bugs, Any questions,suggestions and pulls are welcomed :).  
Maybe I will try to support all Windows x64 verison from win 7 to win 11.  

# Example
(1) NtCreateUserProcess-Post.exe (Default is C:\Program Files\Internet Explorer\iexplore.exe)  
(2) NtCreateUserProcess-Post.exe C:\Windows\system32\notepad.exe  
(3) NtCreateUserProcess-Post.exe "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"  

## Reverse Engineering
After the release of https://github.com/D0pam1ne705/Direct-NtCreateUserProcess and article by D0pam1ne705,  
I think I should also share my the Reverse Engineering results of CreateProcessInternalW (there's no need to keep it private).  
Different from his reverse route, I didn't kernel debug ALPC and csrss.exe,  
but mainly depends on IDA and memory analysis parameter.

## My Build Environment
Visual Studio 2022 (Visual Studio 2019 should work)  
Relase x64

## BasepConstructSxsCreateProcessMessage??
Well, if you think this one is complex and redundant, you can reffer D0pam1ne705 Project 
and simplify the project code without BasepConstructSxsCreateProcessMessage.

## Tested on (Only x64):
 Windows 10 21H2 x64 (19044.1706)  
 Windows 10 21H1 x64 (19043.1023)  
 Windows 10 2004 x64 (19041.264)  
 Windows 10 1909 x64 (18363.2274)  
 Windows Server 2019 x64 (17763.107)  
 Windows Server 2016 x64 (14393)  
 Windows Server 2012 R2 x64 (9600)  
 Windows Server 2012 x64 (9200)  
 Windows Server 2008 R2 x64 (7601)  
 Windows 7 SP1 x64 (7601)  
 Windows Server 2008 x64 (7600）  
 
(win 10 10240->17763 not exactly tested, Will be updated soon)  
