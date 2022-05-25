#include <iostream>
#include "ntapi.hpp"
#include "misc.hpp"
#include "csrss.hpp"
#define ALIGN(x,align)      (((ULONG)(x)+(align)-1UL)&(~((align)-1UL)))

//#define OUTPUT
int wmain(int argc, wchar_t* argv[])
{
	
	LPCWSTR ImageName = NULL;
	if (argc == 1)
	{
		ImageName = L"C:\\Windows\\System32\\dfrgui.exe";
		wprintf(L"[*] Default: %ls\n", ImageName);
	}
	else if (argc == 2)
	{
		ImageName = argv[1];
	}
	else
	{
		wprintf(L"[*] Example: NtCreateUserProcess-Post.exe C:\\Windows\\system32\\notepad.exe\n[!] On Windows 11 Notepad.exe is AppX so it doesn't work.(AppX no supported yet)\n");
		return -1;
	}
	NTSTATUS Status = 0;
	SECTION_IMAGE_INFORMATION SectionImageInfomation = { 0 };
	HANDLE TokenHandle = NULL;
	HANDLE ParentProcessHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID ClientId = { 0 };
	ClientId.UniqueProcess = NtCurrentTeb()->ClientId.UniqueProcess;
	ClientId.UniqueThread = (HANDLE)0;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	PEB peb = { 0 };
	PEB peb2 = { 0 };
	PROCESS_BASIC_INFORMATION mesInfos = { 0 };
	PS_CREATE_INFO CreateInfo = { 0 };
	PS_ATTRIBUTE_LIST AttributeList = { 0 };
	ACTIVATION_CONTEXT_DATA ActivationContextData = { 0 };
	PRTL_USER_PROCESS_PARAMETERS OwnParameters = NtCurrentPeb()->ProcessParameters;
	RTL_USER_PROCESS_PARAMETERS ProcessParameters = { 0 };//Heap 1848
	UNICODE_STRING NtPath = { 0 };
	UNICODE_STRING Win32Path = { 0 };
	UNICODE_STRING CommandLine = { 0 };
	Status = NtOpenProcess(&ParentProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
	if (!NT_SUCCESS(Status))
	{
		wprintf(L"[-] NtOpenProcess: 0x%08x\n", Status);
		return Status;
	}
	wprintf(L"[+] Parent process handle: %p\n", ParentProcessHandle);

	Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &TokenHandle);
	if (!NT_SUCCESS(Status))
	{
		wprintf(L"[-] NtOpenProcessToken: 0x%08x\n", Status);
		return Status;
	}
	wprintf(L"[+] TokenHandle: 0x%p\n", TokenHandle);
	
	if (ImageName != NULL)
	{
		//Use Heap will be better?
		WCHAR NtImageName[MAX_PATH] = { 0 };
		wcscat_s(NtImageName, L"\\??\\");
		wcscat_s(NtImageName, ImageName);
		NtPath.Buffer = NtImageName;
		NtPath.Length = sizeof(WCHAR)*lstrlenW(NtImageName) ;
		NtPath.MaximumLength = sizeof(WCHAR) * lstrlenW(NtImageName)+ sizeof(UNICODE_NULL);
		
		Win32Path.Buffer = (PWSTR)ImageName;
		Win32Path.Length = sizeof(WCHAR) * lstrlenW(ImageName);
		Win32Path.MaximumLength = sizeof(WCHAR) * lstrlenW(ImageName) + sizeof(UNICODE_NULL);

		WCHAR cmdline[MAX_PATH] = { 0 };
		wcscat_s(cmdline, L"\"");// required while blankspace exist =.=
		wcscat_s(cmdline, ImageName);
		wcscat_s(cmdline, L"\"");
		CommandLine.Buffer = (PWSTR)cmdline;
		CommandLine.Length = sizeof(WCHAR) * lstrlenW(cmdline);
		CommandLine.MaximumLength = sizeof(WCHAR) * lstrlenW(cmdline) + sizeof(UNICODE_NULL);
	}
	else
	{
		exit(-1);
	}
	
	CustomSecureZeroMemory(&CreateInfo, sizeof(PS_CREATE_INFO));
	CreateInfo.State = PsCreateInitialState;
	CreateInfo.Size = sizeof(PS_CREATE_INFO);
	CreateInfo.InitState.u1.InitFlags = 3;
	//CreateInfo.InitState.u1.s1.WriteOutputOnExit = TRUE;
	//CreateInfo.InitState.u1.s1.DetectManifest = TRUE;
	//CreateInfo.InitState.u1.s1.ProhibitedImageCharacteristics = IMAGE_FILE_DLL;
	CreateInfo.InitState.AdditionalFileAccess = FILE_READ_ATTRIBUTES | FILE_READ_DATA;

	ULONG ProcessParametersLength = sizeof(RTL_USER_PROCESS_PARAMETERS);
	ProcessParametersLength += (MAX_PATH * sizeof(WCHAR));//CurrentDirectory
	//ProcessParametersLength += ALIGN(OwnParameters->CurrentDirectory.DosPath.Length + sizeof(WCHAR), sizeof(ULONG)); //CurrentDirectory

	ProcessParametersLength += ALIGN(OwnParameters->DllPath.Length + sizeof(WCHAR), sizeof(ULONG));//DllPath
	ProcessParametersLength += ALIGN(Win32Path.Length + sizeof(WCHAR), sizeof(ULONG)); //ImagePathName
	ProcessParametersLength += ALIGN(CommandLine.Length + sizeof(WCHAR), sizeof(ULONG));//CommandLine
	ProcessParametersLength += ALIGN(Win32Path.Length + sizeof(WCHAR), sizeof(ULONG)); //WindowTitle
	ProcessParametersLength += ALIGN(OwnParameters->DesktopInfo.Length + sizeof(WCHAR), sizeof(ULONG));//DesktopInfo
	ProcessParametersLength += 2* ALIGN(2, sizeof(ULONG));//ShellInfo && RuntimeData
	//wprintf(L"Length = %d\n", ProcessParametersLength);
	CustomSecureZeroMemory(&ProcessParameters, ProcessParametersLength);//?
	ProcessParameters.Length = ProcessParametersLength;
	ProcessParameters.MaximumLength = ProcessParametersLength;

	ProcessParameters.Flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
	ProcessParameters.ImagePathName = Win32Path;
	ProcessParameters.CommandLine = CommandLine;
	ProcessParameters.DllPath = OwnParameters->DllPath;
	ProcessParameters.DesktopInfo = OwnParameters->DesktopInfo;
	ProcessParameters.CurrentDirectory.DosPath = OwnParameters->CurrentDirectory.DosPath;
	ProcessParameters.WindowTitle = Win32Path;
	ProcessParameters.Environment = OwnParameters->Environment;
	ProcessParameters.EnvironmentSize = OwnParameters->EnvironmentSize;
	ProcessParameters.EnvironmentVersion = OwnParameters->EnvironmentVersion;
	// Note: WindowFlags is 0 and ShowWindowFlags is 0x1 when launched from the command line, 
	// and both are 0x1 when launched from explorer. This is why the program checks both flags for 0.(x64dbg issue)
	ProcessParameters.WindowFlags = 0x1;
	ProcessParameters.ShowWindowFlags = 0x1;

	ULONG AttributeListCount = 5;
	SIZE_T TotalLength = AttributeListCount * sizeof(PS_ATTRIBUTE) + sizeof(SIZE_T);
	CustomSecureZeroMemory(&AttributeList, TotalLength);
	AttributeList.TotalLength = TotalLength;
	//ReturnLength no need to set in most of time
	AttributeList.Attributes[0].Attribute = PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE);
	AttributeList.Attributes[0].Size = NtPath.Length;
	AttributeList.Attributes[0].Value = (ULONG_PTR)NtPath.Buffer;

	AttributeList.Attributes[1].Attribute = PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE);
	AttributeList.Attributes[1].Size = sizeof(HANDLE);
	AttributeList.Attributes[1].ValuePtr = ParentProcessHandle;//PPID

	AttributeList.Attributes[2].Attribute = PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE);
	AttributeList.Attributes[2].Size = sizeof(SECTION_IMAGE_INFORMATION);
	AttributeList.Attributes[2].ValuePtr = &SectionImageInfomation;

	AttributeList.Attributes[3].Attribute = PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE);
	AttributeList.Attributes[3].Size = sizeof(CLIENT_ID);
	AttributeList.Attributes[3].Value = (ULONG_PTR)&ClientId;

	AttributeList.Attributes[4].Attribute = PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE);
	AttributeList.Attributes[4].Size = sizeof(HANDLE);
	AttributeList.Attributes[4].Value = (ULONG_PTR)TokenHandle;

	Status = NtCreateUserProcess(&hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, NULL, NULL, 0, 1, &ProcessParameters, &CreateInfo, &AttributeList);
	wprintf(L"[*] NtCreateUserProcess: 0x%08x\n", Status);
	if (!NT_SUCCESS(Status))
		return Status;
#ifdef OUTPUT
	CreateInfoOutPut(CreateInfo);
	SectionImageInfomationOutPut(SectionImageInfomation);
#endif
	
	wprintf(L"[*] PID=%d, TID=%d\n", ClientId.UniqueProcess,ClientId.UniqueThread);
	wprintf(L"[*] CustomCallCsrss: 0x%08x\n",
	CallCsrss(hProcess, hThread, CreateInfo, Win32Path, NtPath, ClientId));

	wprintf(L"[*] PEB2Address NtReadVirtualMemory: 0x%08x\n", NtReadVirtualMemory(hProcess, (PVOID)CreateInfo.SuccessState.PebAddressNative, &peb2, sizeof(peb2), 0));
	wprintf(L"[*] peb2.SystemDefaultActivationContextData 0x%p\n", peb2.SystemDefaultActivationContextData);
	wprintf(L"[*] peb2.ActivationContextData 0x%p\n", peb2.ActivationContextData);
	wprintf(L"[*] NtResumeThread: 0x%08x\n", NtResumeThread(hThread, 0));

	NtClose(ParentProcessHandle);
	NtClose(TokenHandle);
	NtClose(hProcess);
	NtClose(hThread);
	return 0;
}