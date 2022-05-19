# NtCreateUserProcess-Post
NtCreateUserProcess with CsrClientCallServer for mainstream Windows x64 version.  
Maybe I will try to support all Windows x64 verison from win 7 to win 11.  
This project could be useless, however it's also useful to learn!  
Any questions,suggestions and pulls are welcomed .


# Reverse Engineering
After the release of https://github.com/D0pam1ne705/Direct-NtCreateUserProcess and article by d0pam1ne705,  
I think I should also share my the Reverse Engineering results of CreateProcessInternalW (there's no need to hide it).  
Different from his reverse route, I didn't kernel debug ALPC and csrss.exe,  
but mainly depends on IDA and memory analysis parameter.

# My Build Environment
Visual Studio 2022 (Visual Studio 2019 should work)
Relase x64

# Tested on (x64)
 Windows 10 21H2 (19044.1706)  
 Windows 10 21H1 (19043.1023)  
 Windows 10 2004 (19041.264)  
 Windows 10 1909 (18363.2274)  
 Windows Server 2019 (17763.107)  
 Windows Server 2016 (14393)  
 Windows Server 2012 R2 (9600)  
 Windows Server 2012 (9200)  
 Windows Server 2008 R2 (7601)  
 Windows 7 SP1 (7601)  
 Windows Server 2008 (7600）  
 
(Will be updated soon)
