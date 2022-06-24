#include <iostream>
#include "ntapi.hpp"
#include "misc.hpp"
#include "csrss.hpp"

//#define OUTPUT
void helpinfo()
{
	wprintf(L"[*] Example: \n"
			 "NtCreateUserProcess-Native.exe -c C:\\Windows\\system32\\notepad.exe\n"
			 "NtCreateUserProcess-Native.exe -c C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -i 1\n\n"
			 "[*] -c (Optional) ImagePath, Notice double quote is requied when blankspace in path like\n"
			 " C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n\n"
			 "[*] -i (Optional) Interact for console process like C:\\Windows\\system32\\cmd.exe\n"
			 "-i 0: (Default) None of any interact mode will be used, like CREATE_NEW_CONSOLE\n"
			 "-i 1: StdHandle via AttributeList, like bInheritHandles = FALSE\n"
			 "-i 2: Set ProcessParameters Std Input,Output,OutError with CurrentProcessParameters Value, like bInheritHandles = TRUE\n\n");
	wprintf(L"[!] On Windows 11 Notepad.exe is AppX so it doesn't work. (AppX isn't supported in this project)\n");
}
int wmain(int argc, wchar_t* argv[])
{
	
	LPCWSTR ImageName = NULL;
	int Interact = 0;
	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		case 'h':
			helpinfo();
			return 0;
		case 'c':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				ImageName = argv[1];
				wprintf(L"[*] ImageName = %ls\n", ImageName);
			}
			else
			{
				wprintf(L"[-] Missing value for option: -c\n");
				helpinfo();
				return -1;
			}
			break;
		case 'i':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-' && argv[1])
			{
				swscanf_s(argv[1], L"%d", &Interact);
				if (Interact < 0 || Interact > 3)
				{
					wprintf(L"[-] Invaid value for option: -i\n");
					return -1;
				}
			}
			else
			{
				wprintf(L"[-] Missing value for option: -i\n");
				helpinfo();
				return -1;
			}
			break;
		default:
			wprintf(L"[-] Invalid argument: %ls\n", argv[1]);
			helpinfo();
			return -1;
		}
		++argv;
		--argc;
	}
	if (!ImageName)
	{
		ImageName = L"C:\\Windows\\System32\\dfrgui.exe";
		wprintf(L"[*] Default ImageName: %ls\n", ImageName);
	}
	wprintf(L"[*] Interact Mode = %d\n", Interact);

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
	ULONG ProcessFlags = 0;
	PEB peb = { 0 };
	PEB peb2 = { 0 };
	PROCESS_BASIC_INFORMATION mesInfos = { 0 };
	PS_CREATE_INFO CreateInfo = { 0 };
	PS_ATTRIBUTE_LIST AttributeList = { 0 };
	PS_STD_HANDLE_INFO StdHandle = { 0 };
	ACTIVATION_CONTEXT_DATA ActivationContextData = { 0 };
	PRTL_USER_PROCESS_PARAMETERS OwnParameters = NtCurrentPeb()->ProcessParameters;
	RTL_USER_PROCESS_PARAMETERS ProcessParameters = { 0 };
	UNICODE_STRING NtImagePath = { 0 };
	UNICODE_STRING Win32ImagePath = { 0 };
	UNICODE_STRING CommandLine = { 0 };

	Status = NtOpenProcess(&ParentProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
	ClientId = { 0 };
	if (!NT_SUCCESS(Status))
	{
		wprintf(L"[-] NtOpenProcess: 0x%08x\n", Status);
		return Status;
	}
	wprintf(L"[+] Parent process handle: %p\n", ParentProcessHandle);
	
	Status = NtOpenProcessToken(ParentProcessHandle, TOKEN_ALL_ACCESS, &TokenHandle);
	if (!NT_SUCCESS(Status))
	{
		wprintf(L"[-] NtOpenProcessToken: 0x%08x\n", Status);
		return Status;
	}
	wprintf(L"[+] TokenHandle: 0x%p\n", TokenHandle);
	NtClose(ParentProcessHandle);
	ParentProcessHandle = NULL;//ov0
	
	if (ImageName != NULL)
	{
		//Use Heap will be better?
		WCHAR NtImageName[MAX_PATH] = { 0 };
		wcscat_s(NtImageName, L"\\??\\");
		wcscat_s(NtImageName, ImageName);
		NtImagePath.Buffer = NtImageName;
		NtImagePath.Length = sizeof(WCHAR)*lstrlenW(NtImageName) ;
		NtImagePath.MaximumLength = sizeof(WCHAR) * lstrlenW(NtImageName)+ sizeof(UNICODE_NULL);
		
		Win32ImagePath.Buffer = (PWSTR)ImageName;
		Win32ImagePath.Length = sizeof(WCHAR) * lstrlenW(ImageName);
		Win32ImagePath.MaximumLength = sizeof(WCHAR) * lstrlenW(ImageName) + sizeof(UNICODE_NULL);

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
		return -1;
	}
	
	CustomSecureZeroMemory(&CreateInfo, sizeof(PS_CREATE_INFO));//CREATE_NEW_PROCESS_GROUP
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
	ProcessParametersLength += ALIGN(Win32ImagePath.Length + sizeof(WCHAR), sizeof(ULONG)); //ImagePathName
	ProcessParametersLength += ALIGN(CommandLine.Length + sizeof(WCHAR), sizeof(ULONG));//CommandLine
	ProcessParametersLength += ALIGN(Win32ImagePath.Length + sizeof(WCHAR), sizeof(ULONG)); //WindowTitle
	ProcessParametersLength += ALIGN(OwnParameters->DesktopInfo.Length + sizeof(WCHAR), sizeof(ULONG));//DesktopInfo
	ProcessParametersLength += 2* ALIGN(2, sizeof(ULONG));//ShellInfo && RuntimeData
	//wprintf(L"Length = %d\n", ProcessParametersLength);
	//ProcessParametersLength is not good! need to fix...

	CustomSecureZeroMemory(&ProcessParameters, ProcessParametersLength);//?
	ProcessParameters.Length = ProcessParametersLength;
	ProcessParameters.MaximumLength = ProcessParametersLength;

	ProcessParameters.Flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
	ProcessParameters.ImagePathName = Win32ImagePath;
	ProcessParameters.CommandLine = CommandLine;
	ProcessParameters.DllPath = OwnParameters->DllPath;//old
	ProcessParameters.DesktopInfo = OwnParameters->DesktopInfo;
	ProcessParameters.ShellInfo = OwnParameters->ShellInfo;
	ProcessParameters.CurrentDirectory.DosPath = OwnParameters->CurrentDirectory.DosPath;
	ProcessParameters.WindowTitle = Win32ImagePath;
	ProcessParameters.Environment = OwnParameters->Environment;
	ProcessParameters.EnvironmentSize = OwnParameters->EnvironmentSize; 
	ProcessParameters.EnvironmentVersion = OwnParameters->EnvironmentVersion; //EnvironmentVersion coudle be 0 ?
	//==================================================================================
	ProcessParameters.ProcessGroupId = NtCurrentPeb()->ProcessParameters->ProcessGroupId; //dwCreationFlags & CREATE_NEW_PROCESS_GROUP == 0

	// 7601 and below OS std io are not hold with conhost.exe directly
	if (Interact == 0)
	{
		wprintf(L"[*] CREATE_NEW_CONSOLE...\n");
		ProcessParameters.ConsoleHandle = NULL;//(HANDLE)-2i64 = CONSOLE_NEW_CONSOLE
	}
	else
	{
		ProcessParameters.ConsoleHandle = !ConhostConsoleHandle || OSBuildNumber <= 7601 ? OwnParameters->ConsoleHandle : ConhostConsoleHandle;
	}

	//[bInheritHandles == TRUE <->ProcessFlags & 4) ...]
	// 
	// if ParentProcessHandle != NULL, need to set for StdHandle Mode 2 ???
	// I don't know...
	// 
	// ProcessParameters->StandardInput = StartInfo->hStdInput;
	// ProcessParameters->StandardOutput = StartInfo->hStdOutput;
	// ProcessParameters->StandardError = StartInfo->hStdError;

	if (Interact == 2 || OSBuildNumber <= 7601)// OSBuildNumber >= ? && ParentProcessHandle
	{
		//7601 and below OS std io are not hold with conhost.exe directly
		wprintf(L"[*] Redirect the Child Process's Standard File IO via ProcessParameters!\n");
		ProcessParameters.StandardInput = OwnParameters->StandardInput;
		ProcessParameters.StandardOutput = OwnParameters->StandardOutput;
		ProcessParameters.StandardError = OwnParameters->StandardError;
	}
	/*
	wprintf(L"[*] ProcessParameters.ConsoleHandle = 0x%p\n", ProcessParameters.ConsoleHandle);
	wprintf(L"[*] ProcessParameters.StandardInput = 0x%p\n", ProcessParameters.StandardInput);
	wprintf(L"[*] ProcessParameters.StandardOutput = 0x%p\n", ProcessParameters.StandardOutput);
	wprintf(L"[*] ProcessParameters.StandardError = 0x%p\n", ProcessParameters.StandardError);
	*/
	if (Interact == 2)//bInheritHandles == TRUE
		ProcessFlags |= PROCESS_CREATE_FLAGS_INHERIT_HANDLES;
	else
		ProcessFlags &= ~PROCESS_CREATE_FLAGS_INHERIT_HANDLES;

	// Note: WindowFlags is 0 and ShowWindowFlags is 0x1 when launched from the command line, 
	// and both are 0x1 when launched from explorer. This is why the program checks both flags for 0.(x64dbg issue)???
	ProcessParameters.WindowFlags = 0x0;
	ProcessParameters.ShowWindowFlags = SW_SHOWNORMAL;//SW_SHOWNORMAL SW_HIDE

	AttributeList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList.Attributes[0].Size = NtImagePath.Length;
	AttributeList.Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

	AttributeList.Attributes[1].Attribute = PS_ATTRIBUTE_IMAGE_INFO;
	AttributeList.Attributes[1].Size = sizeof(SECTION_IMAGE_INFORMATION);
	AttributeList.Attributes[1].ValuePtr = &SectionImageInfomation;

	AttributeList.Attributes[2].Attribute = PS_ATTRIBUTE_CLIENT_ID;
	AttributeList.Attributes[2].Size = sizeof(CLIENT_ID);
	AttributeList.Attributes[2].Value = (ULONG_PTR)&ClientId;

	AttributeList.Attributes[3].Attribute = PS_ATTRIBUTE_TOKEN;
	AttributeList.Attributes[3].Size = sizeof(HANDLE);
	AttributeList.Attributes[3].Value = (ULONG_PTR)TokenHandle;//LPE, CreateProcessWithToken
	ULONG AttributeCount = 4;

	if (ParentProcessHandle)
	{
		wprintf(L"[*] Set ParentProcess Handle!\n");
		AttributeList.Attributes[AttributeCount].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
		AttributeList.Attributes[AttributeCount].Size = sizeof(HANDLE);
		AttributeList.Attributes[AttributeCount].ValuePtr = ParentProcessHandle;//PPID
		AttributeCount++;
	}
	if (Interact == 1 && (OSBuildNumber > 9600 || !ParentProcessHandle))
	{
		StdHandle.StdHandleSubsystemType = IMAGE_SUBSYSTEM_WINDOWS_CUI;
		if (!ParentProcessHandle)// none of CREATE_NO_WINDOW CREATE_NEW_CONSOLE DETACHED_PROCESS
		{
			wprintf(L"[*] StdHandle Mode 1\n");
			StdHandle.Flags = StdHandle.Flags & -0x20 | PsRequestDuplicate; 
		}
		else//StdHandle with ParentProcessHandle is supported since...
		{
			wprintf(L"[*] StdHandle Mode 2, not work...\n");
			StdHandle.Flags = StdHandle.Flags & -0x20 | PsAlwaysDuplicate;
		}
		if (OSBuildNumber <= 7601)
		{
			StdHandle.PseudoHandleMask |= ((ULONGLONG)ProcessParameters.StandardInput & 0x10000003) == 3 ? PS_STD_INPUT_HANDLE : 0;
			StdHandle.PseudoHandleMask |= ((ULONGLONG)ProcessParameters.StandardOutput & 0x10000003) == 3 ? PS_STD_OUTPUT_HANDLE : 0;
			StdHandle.PseudoHandleMask |= ((ULONGLONG)ProcessParameters.StandardError & 0x10000003) == 3 ? PS_STD_ERROR_HANDLE : 0;
			wprintf(L"[*] Old StdHandle.PseudoHandleMask Set!\n");
		}
		AttributeList.Attributes[AttributeCount].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
		AttributeList.Attributes[AttributeCount].Size = sizeof(PS_STD_HANDLE_INFO);
		AttributeList.Attributes[AttributeCount].ReturnLength = 0;
		AttributeList.Attributes[AttributeCount].ValuePtr = &StdHandle;
		AttributeCount++;
		
	}
	AttributeList.TotalLength = AttributeCount * sizeof(PS_ATTRIBUTE) + sizeof(SIZE_T);

	wprintf(L"[*] AttributeList.TotalLength = %lld, AttributeCount = %ld\n", AttributeList.TotalLength, AttributeCount);
	Status = NtCreateUserProcess(&hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, NULL, NULL, ProcessFlags, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, &ProcessParameters, &CreateInfo, &AttributeList);
	wprintf(L"[*] NtCreateUserProcess: 0x%08x\n", Status);
	if (!NT_SUCCESS(Status))
		return Status;
#ifdef OUTPUT
	CreateInfoOutPut(CreateInfo);
	SectionImageInfomationOutPut(SectionImageInfomation);
#endif
	
	wprintf(L"[*] PID=%lld, TID=%lld\n", (ULONGLONG)ClientId.UniqueProcess, (ULONGLONG)ClientId.UniqueThread);
	wprintf(L"[*] CustomCallCsrss: 0x%08x\n",
	CallCsrss(hProcess, hThread, CreateInfo, Win32ImagePath, NtImagePath, ClientId, SectionImageInfomation));
	
	//wprintf(L"[*] PEB2Address NtReadVirtualMemory: 0x%08x\n", NtReadVirtualMemory(hProcess, (PVOID)CreateInfo.SuccessState.PebAddressNative, &peb2, sizeof(peb2), 0));
	wprintf(L"[*] peb2.SystemDefaultActivationContextData 0x%p\n", peb2.SystemDefaultActivationContextData);
	wprintf(L"[*] peb2.ActivationContextData 0x%p\n", peb2.ActivationContextData);
	wprintf(L"[*] NtResumeThread: 0x%08x\n", NtResumeThread(hThread, 0));
	
	if (Interact != 0)
	{
		//For test only, there is no need to waitfor handle in fact.
		NtWaitForSingleObject(hThread, FALSE, NULL);
		wprintf(L"[!] New Process Exited!\n");
	}
	if (ParentProcessHandle)
	{
		NtClose(ParentProcessHandle);
		ParentProcessHandle = NULL;
	}
	NtClose(TokenHandle);

	NtClose(hProcess);
	NtClose(hThread);
	NtClose(CreateInfo.SuccessState.FileHandle);
	NtClose(CreateInfo.SuccessState.SectionHandle);
	ProcessParameters = { 0 };
	CustomSecureZeroMemory(&ProcessParameters, ProcessParametersLength);//?
	AttributeList = { 0 };
	CustomSecureZeroMemory(&AttributeList, AttributeList.TotalLength);
	return 0;
}