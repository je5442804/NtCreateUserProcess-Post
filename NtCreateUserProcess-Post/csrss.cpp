#include "csrss.hpp"
#include "ntapi.hpp"
#include <stdio.h>

// CsrPortHandle and CsrPortMemoryRemoteDelta can be init from CsrpConnectToServer? but we won't do it...  Ovo
NTSTATUS CsrClientCallServer(PCSR_API_MSG ApiMessage, PCSR_CAPTURE_BUFFER  CaptureBuffer, ULONG ApiNumber, ULONG DataLength)
{
	//Without Any SecureCheck is Unsafe but Faster!
	NTSTATUS Status = -1;
	ApiMessage->ApiNumber = ApiNumber & 0xEFFFFFFF;
	ApiMessage->h.u2.ZeroInit = 0;
	ApiMessage->h.u1.Length = (DataLength | (DataLength << 16)) + (((sizeof(CSR_API_MSG) - sizeof(ApiMessage->u)) << 16) | (FIELD_OFFSET(CSR_API_MSG, u) - sizeof(ApiMessage->h)));// +0x400018
	ApiMessage->CaptureBuffer = (PCSR_CAPTURE_BUFFER)((char*)CaptureBuffer + CsrPortMemoryRemoteDelta);
	CaptureBuffer->FreeSpace = 0;//Mark the fact that we are done allocating space from the end of  the capture buffer.
	ULONG_PTR Pointer = 0;
	ULONG CountPointers = CaptureBuffer->CountMessagePointers;
	PULONG_PTR PointerOffsets = CaptureBuffer->MessagePointerOffsets;
	while (CountPointers--) {
		Pointer = *PointerOffsets++;
		if (Pointer != 0) {
			*(PULONG_PTR)Pointer += CsrPortMemoryRemoteDelta;
			PointerOffsets[-1] = Pointer - (ULONG_PTR)ApiMessage;
		}
	}
	/* SIZE
	CSR_API_MSG = 432
	DataLength = 536
	BASE_API_MSG = 600?
	*/
	SIZE_T ALPC_Size = 952;//unknow size? TotalLength??
	//tip: CsrPortHandle is related to OS version and (debug?)
	Status = NtAlpcSendWaitReceivePort(//in csrclientcallserver,since win 10 2004 but work well in win 7/2008/2012....
		CsrPortHandle,
		ALPC_MSGFLG_SYNC_REQUEST,
		(PPORT_MESSAGE)ApiMessage,
		0,
		(PPORT_MESSAGE)ApiMessage,
		&ALPC_Size,// [Optional] 
		0,
		0
	);
	// STATUS_ILLEGAL_FUNCTION?
	wprintf(L"[*] ALPC Status: 0x%08x\n", Status);
	wprintf(L"[*] ALPC ApiMessage ReturnStatus : 0x%08x\n", ApiMessage->ReturnValue);
	/*
	if (!NT_SUCCESS(Status) || !NT_SUCCESS(ApiMessage->ReturnValue))
	{
		wprintf(L"[-] NtAlpcSendWaitReceivePort Fail,retry with LPC...\n");
		Status = NtRequestWaitReplyPort(CsrPortHandle, &TempApiMessage, (PPORT_MESSAGE)ApiMessage);
		wprintf(L"[*] LPC Status: 0x%08x\n", Status);
		wprintf(L"[*] LPC ApiMessage ReturnStatus: 0x%08x\n", ApiMessage->ReturnValue);
	}
	*/

	ApiMessage->CaptureBuffer = (PCSR_CAPTURE_BUFFER)((char*)CaptureBuffer - CsrPortMemoryRemoteDelta);
	//
	// Loop over all of the pointers to Port Memory within the message
	// itself and convert them into client pointers.  Also, convert
	// the offsets pointers to pointers into back into pointers
	//
	PointerOffsets = CaptureBuffer->MessagePointerOffsets;
	CountPointers = CaptureBuffer->CountMessagePointers;
	while (CountPointers--) {
		Pointer = *PointerOffsets++;
		if (Pointer != 0) {
			Pointer += (ULONG_PTR)ApiMessage;//Length
			PointerOffsets[-1] = Pointer;
			*(PULONG_PTR)Pointer -= CsrPortMemoryRemoteDelta;
		}
	}
	if (!NT_SUCCESS(Status))
		ApiMessage->ReturnValue = Status;
	return ApiMessage->ReturnValue;
}

NTSTATUS CallCsrss(HANDLE hProcess, HANDLE hThread, PS_CREATE_INFO CreateInfo, UNICODE_STRING Win32Path, UNICODE_STRING NtPath, CLIENT_ID ClientId,USHORT DllCharacteristics)
{
	//ULONG NtMajorVersion = *(PULONG)(0x7FFE0000 + 0x26C);
	//ULONG NtMinorVersion = *(PULONG)(0x7FFE0000 + 0x270);
	//wprintf(L"Pre CsrPortHandle: 0x%08x\n", CsrPortHandle);
	//wprintf(L"Pre CsrPortMemoryRemoteDelta: 0x%p\n", CsrPortMemoryRemoteDelta);
	//wprintf(L"Pre BasepConstructSxsCreateProcessMessage_2008_Address: 0x%p\n", BasepConstructSxsCreateProcessMessage_2008_Address);

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
	CsrCaptureMessageMultiUnicodeStringsInPlace_t CsrCaptureMessageMultiUnicodeStringsInPlace = (CsrCaptureMessageMultiUnicodeStringsInPlace_t)GetProcAddress(ntdll, "CsrCaptureMessageMultiUnicodeStringsInPlace");
	_BasepConstructSxsCreateProcessMessage BasepConstructSxsCreateProcessMessage_18 = (_BasepConstructSxsCreateProcessMessage)GetProcAddress(kernel32, "BasepConstructSxsCreateProcessMessage");
	_CsrClientCallServer CsrClientCallServer_ntdll = (_CsrClientCallServer)GetProcAddress(ntdll, "CsrClientCallServer");

	wprintf(L"[*] kernel32!BasepConstructSxsCreateProcessMessage address: %p\n", BasepConstructSxsCreateProcessMessage_18);
	wprintf(L"[*] ntdll!CsrCaptureMessageMultiUnicodeStringsInPlace address: %p\n", CsrCaptureMessageMultiUnicodeStringsInPlace);
	wprintf(L"[*] ntdll!CsrClientCallServer_ntdll address: %p\n", CsrClientCallServer_ntdll);

	HANDLE TokenHandle = NULL;
	NTSTATUS Status = NULL;
	wprintf(L"[*] NtOpenProcessToken: %d\n", NtOpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &TokenHandle));
	wprintf(L"[*] TokenHandle: 0x%p\n", TokenHandle);

	PCSR_CAPTURE_BUFFER CaptureBuffer = 0;
	Sxs_CreateProcess_UtilityStruct SxsCreateProcessUtilityStruct = { 0 };//88
	RtlSecureZeroMemory(&SxsCreateProcessUtilityStruct, sizeof(SxsCreateProcessUtilityStruct));
	BASE_API_MSG BaseAPIMessage = { 0 };
	PUNICODE_STRING CsrStringsToCapture[6] = { 0 };
	CSR_API_NUMBER CSRAPINumber = 0x10000;
	ULONG DataLength = 0;
	wprintf(L"OS: %d\n", OSBuildNumber);

	if (OSBuildNumber >= 18985)//win 10 19041 [2004//20H1] ? 19000
	{
		wprintf(L"[*] Windows 10 2004+ | Windows Server 2022\n");
		PBASE_CREATEPROCESS_MSG BaseCreateProcessMessage = &BaseAPIMessage.u.BaseCreateProcess;
		RtlSecureZeroMemory(&BaseCreateProcessMessage->Sxs, sizeof(BaseCreateProcessMessage->Sxs));
		BaseCreateProcessMessage->ProcessHandle = hProcess;
		BaseCreateProcessMessage->ThreadHandle = hThread;
		BaseCreateProcessMessage->ClientId = ClientId;
		BaseCreateProcessMessage->CreationFlags = EXTENDED_STARTUPINFO_PRESENT | IDLE_PRIORITY_CLASS;//0x80040 ?? &0xFFFFFFFC
		BaseCreateProcessMessage->VdmBinaryType = NULL;

		
		//BOOLEAN testflag = (CreateInfo.InitState.u1.InitFlags >> 2) & 1;
		Status = BasepConstructSxsCreateProcessMessage_18(
			&NtPath,
			&Win32Path,
			CreateInfo.SuccessState.FileHandle,
			hProcess,
			CreateInfo.SuccessState.SectionHandle,
			TokenHandle,
			(CreateInfo.InitState.u1.InitFlags & 0x4) != 0,//0x4 
			0,//Unknow_CompatCache
			0,//AppCompatSxsData
			0,//AppCompatSxsDataSize
			(DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0,//DllCharacteristics
			NULL,//AppXPath?
			(PPEB)CreateInfo.SuccessState.PebAddressNative,
			(PVOID)CreateInfo.SuccessState.ManifestAddress,
			CreateInfo.SuccessState.ManifestSize,
			&CreateInfo.SuccessState.CurrentParameterFlags,
			&BaseCreateProcessMessage->Sxs,
			&SxsCreateProcessUtilityStruct
		);
		wprintf(L"[+] BasepConstructSxsCreateProcessMessage: 0x%08x\n", Status);

		BaseCreateProcessMessage->PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;

		CsrStringsToCapture[0] = &BaseCreateProcessMessage->Sxs.Win32Path;//CsrStringsToCapture[0] = &BaseCreateProcessMessage->Sxs.Win32Path;
		CsrStringsToCapture[1] = &BaseCreateProcessMessage->Sxs.NtPath;//8+8 Manifest.Path (UNICODE_STRING) | FileHandle? ??????
		CsrStringsToCapture[2] = &BaseCreateProcessMessage->Sxs.CacheSxsLanguageBuffer;//Win32AssemblyDirectory 136
		CsrStringsToCapture[3] = &BaseCreateProcessMessage->Sxs.AssemblyIdentity;

		CSRAPINumber = 0x1001D;//since 2004
		DataLength = sizeof(*BaseCreateProcessMessage);//536 = 0x1c8
			
	}
	else if (OSBuildNumber >= 18214)// win 10 1903 | win 10 1909
	{
		//Windows 10 1903 not tested yet
		wprintf(L"[*] Windows 10 1903 | Windows 10 1909\n");
		PBASE_CREATEPROCESS_MSG_2012 BaseCreateProcessMessage = &BaseAPIMessage.u.BaseCreateProcess_2012;//OMG
		RtlSecureZeroMemory(&BaseCreateProcessMessage->Sxs, sizeof(BaseCreateProcessMessage->Sxs));
		BaseCreateProcessMessage->ProcessHandle = hProcess;
		BaseCreateProcessMessage->ThreadHandle = hThread;
		BaseCreateProcessMessage->ClientId = ClientId;
		BaseCreateProcessMessage->CreationFlags = EXTENDED_STARTUPINFO_PRESENT | IDLE_PRIORITY_CLASS;
		BaseCreateProcessMessage->VdmBinaryType = NULL;

		Status = BasepConstructSxsCreateProcessMessage_18(
			&NtPath,
			&Win32Path,
			CreateInfo.SuccessState.FileHandle,
			hProcess,
			CreateInfo.SuccessState.SectionHandle,
			TokenHandle,
			(CreateInfo.InitState.u1.InitFlags & 0x4) != 0,//0x4 
			0,
			0,//AppCompatSxsData
			0,//AppCompatSxsDataSize
			(DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0,//DllCharacteristics
			NULL,
			(PPEB)CreateInfo.SuccessState.PebAddressNative,
			(PVOID)CreateInfo.SuccessState.ManifestAddress,
			CreateInfo.SuccessState.ManifestSize,
			&CreateInfo.SuccessState.CurrentParameterFlags,
			&BaseCreateProcessMessage->Sxs,
			&SxsCreateProcessUtilityStruct
		);
		wprintf(L"[+] BasepConstructSxsCreateProcessMessage: 0x%08x\n", Status);


		BaseCreateProcessMessage->PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;

		CsrStringsToCapture[0] = &BaseCreateProcessMessage->Sxs.Win32Path;
		CsrStringsToCapture[1] = &BaseCreateProcessMessage->Sxs.NtPath;
		CsrStringsToCapture[2] = &BaseCreateProcessMessage->Sxs.CacheSxsLanguageBuffer;
		CsrStringsToCapture[3] = &BaseCreateProcessMessage->Sxs.AssemblyIdentity;

		DataLength = sizeof(*BaseCreateProcessMessage);//536 = 0x1c8
	}
	else if (OSBuildNumber >= 17763)//win server 2019 | win 10 1809
	{
		//Windows 10 1803 not tested yet
		wprintf(L"[*] |  Windows 10 1803 | Windows 10 1809 | Windows Server 2019\n");
		PBASE_CREATEPROCESS_MSG_2016 BaseCreateProcessMessage;
		BaseCreateProcessMessage = &BaseAPIMessage.u.BaseCreateProcess_2016;
		RtlSecureZeroMemory(&BaseCreateProcessMessage->Sxs, sizeof(BaseCreateProcessMessage->Sxs));
		BaseCreateProcessMessage->ProcessHandle = hProcess;
		BaseCreateProcessMessage->ThreadHandle = hThread;
		BaseCreateProcessMessage->ClientId = ClientId;
		BaseCreateProcessMessage->CreationFlags = EXTENDED_STARTUPINFO_PRESENT | IDLE_PRIORITY_CLASS;
		BaseCreateProcessMessage->VdmBinaryType = NULL;
		Status = BasepConstructSxsCreateProcessMessage_18(
			&NtPath,
			&Win32Path,
			CreateInfo.SuccessState.FileHandle,
			hProcess,
			CreateInfo.SuccessState.SectionHandle,
			TokenHandle,
			(CreateInfo.InitState.u1.InitFlags & 0x4) != 0,
			0,
			0,
			0,
			(DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0,//
			NULL,
			(PPEB)CreateInfo.SuccessState.PebAddressNative,
			(PVOID)CreateInfo.SuccessState.ManifestAddress,
			CreateInfo.SuccessState.ManifestSize,
			&CreateInfo.SuccessState.CurrentParameterFlags,
			&BaseCreateProcessMessage->Sxs,
			&SxsCreateProcessUtilityStruct
		);
		wprintf(L"[+] BasepConstructSxsCreateProcessMessage: 0x%08x\n", Status);

		BaseCreateProcessMessage->PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;

		CsrStringsToCapture[0] = &BaseCreateProcessMessage->Sxs.Win32Path;
		CsrStringsToCapture[1] = &BaseCreateProcessMessage->Sxs.NtPath;
		CsrStringsToCapture[2] = &BaseCreateProcessMessage->Sxs.CacheSxsLanguageBuffer;
		CsrStringsToCapture[3] = &BaseCreateProcessMessage->Sxs.AssemblyIdentity;

		DataLength = sizeof(*BaseCreateProcessMessage);//264

	}
	else if (OSBuildNumber >= 10240)//win 10 10240 到win 10 17763 [1809] 还没测试和逆向,只弄了个2016,先这样吧
	{
		wprintf(L"[*] Windows 10 10240-17763 ??? | Windows Server 2016\n");
		PBASE_CREATEPROCESS_MSG_2016 BaseCreateProcessMessage;
		BaseCreateProcessMessage = &BaseAPIMessage.u.BaseCreateProcess_2016;
		RtlSecureZeroMemory(&BaseCreateProcessMessage->Sxs, sizeof(BaseCreateProcessMessage->Sxs));

		BaseCreateProcessMessage->ProcessHandle = hProcess;
		BaseCreateProcessMessage->ThreadHandle = hThread;
		BaseCreateProcessMessage->ClientId = ClientId;
		BaseCreateProcessMessage->CreationFlags = EXTENDED_STARTUPINFO_PRESENT | IDLE_PRIORITY_CLASS;
		BaseCreateProcessMessage->VdmBinaryType = NULL;
		
		_BasepConstructSxsCreateProcessMessage_2016 BasepConstructSxsCreateProcessMessage_2016 = (_BasepConstructSxsCreateProcessMessage_2016)BasepConstructSxsCreateProcessMessage_18;
		Status = BasepConstructSxsCreateProcessMessage_2016(
			&NtPath,
			&Win32Path,
			CreateInfo.SuccessState.FileHandle,
			hProcess,
			CreateInfo.SuccessState.SectionHandle,
			TokenHandle,
			FALSE,//AlreadyCheck
			FALSE,//IsRemovableMedia
			(CreateInfo.InitState.u1.InitFlags & 0x4) != 0,
			0,
			0,
			0,
			(DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0,
			NULL,
			(PPEB)CreateInfo.SuccessState.PebAddressNative,
			(PVOID)CreateInfo.SuccessState.ManifestAddress,
			CreateInfo.SuccessState.ManifestSize,
			&CreateInfo.SuccessState.CurrentParameterFlags,
			&BaseCreateProcessMessage->Sxs,
			&SxsCreateProcessUtilityStruct
		);
		wprintf(L"[+] BasepConstructSxsCreateProcessMessage: 0x%08x\n", Status);
		
		BaseCreateProcessMessage->PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;

		CsrStringsToCapture[0] = &BaseCreateProcessMessage->Sxs.Win32Path;
		CsrStringsToCapture[1] = &BaseCreateProcessMessage->Sxs.NtPath;
		CsrStringsToCapture[2] = &BaseCreateProcessMessage->Sxs.CacheSxsLanguageBuffer;
		CsrStringsToCapture[3] = &BaseCreateProcessMessage->Sxs.AssemblyIdentity;

		DataLength = sizeof(*BaseCreateProcessMessage);//264		
	}
	else if (OSBuildNumber >= 8423)
	{
		//sizeof(BASE_SXS_CREATEPROCESS_MSG_2012);//->sxs = 192
		//sizeof(BASE_CREATEPROCESS_MSG_2012);// createprocess total-> 272
		PBASE_CREATEPROCESS_MSG_2012 BaseCreateProcessMessage = &BaseAPIMessage.u.BaseCreateProcess_2012;
		RtlSecureZeroMemory(&BaseCreateProcessMessage->Sxs, sizeof(BaseCreateProcessMessage->Sxs));

		BaseCreateProcessMessage->ProcessHandle = hProcess;
		BaseCreateProcessMessage->ThreadHandle = hThread;
		BaseCreateProcessMessage->ClientId = ClientId;
		BaseCreateProcessMessage->CreationFlags = EXTENDED_STARTUPINFO_PRESENT | IDLE_PRIORITY_CLASS;
		BaseCreateProcessMessage->VdmBinaryType = NULL;
		
		if (OSBuildNumber <= 9200)
		{
			wprintf(L"[*] Windows 8 | Windows Server 2012 \n");
			_BasepConstructSxsCreateProcessMessage_2012_old BasepConstructSxsCreateProcessMessage_2012 = (_BasepConstructSxsCreateProcessMessage_2012_old)BasepConstructSxsCreateProcessMessage_18;
			Status = BasepConstructSxsCreateProcessMessage_2012(
				&NtPath,
				&Win32Path,
				CreateInfo.SuccessState.FileHandle,
				hProcess,
				CreateInfo.SuccessState.SectionHandle,
				FALSE,//AlreadyCheck
				FALSE,//IsRemovableMedia
				(CreateInfo.InitState.u1.InitFlags & 0x4) != 0,
				0,
				0,
				0,
				(DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0,
				NULL,
				(PPEB)CreateInfo.SuccessState.PebAddressNative,
				(PVOID)CreateInfo.SuccessState.ManifestAddress,
				CreateInfo.SuccessState.ManifestSize,
				&CreateInfo.SuccessState.CurrentParameterFlags,
				&BaseCreateProcessMessage->Sxs,
				&SxsCreateProcessUtilityStruct
			);
		}
		else
		{
			wprintf(L"[*] Windows 8.1 | Windows Server 2012 R2\n");
			BaseCreateProcessMessage->Sxs.UnknowFlags = -1;
			_BasepConstructSxsCreateProcessMessage_2016 BasepConstructSxsCreateProcessMessage_2012 = (_BasepConstructSxsCreateProcessMessage_2016)BasepConstructSxsCreateProcessMessage_18;
			Status = BasepConstructSxsCreateProcessMessage_2012(
				&NtPath,
				&Win32Path,
				CreateInfo.SuccessState.FileHandle,
				hProcess,
				CreateInfo.SuccessState.SectionHandle,
				TokenHandle,
				FALSE,//AlreadyCheck
				FALSE,//IsRemovableMedia
				(CreateInfo.InitState.u1.InitFlags & 0x4) != 0,
				0,
				0,
				0,
				(DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0,
				NULL,
				(PPEB)CreateInfo.SuccessState.PebAddressNative,
				(PVOID)CreateInfo.SuccessState.ManifestAddress,
				CreateInfo.SuccessState.ManifestSize,
				&CreateInfo.SuccessState.CurrentParameterFlags,
				&BaseCreateProcessMessage->Sxs,
				&SxsCreateProcessUtilityStruct
			);
		}
		wprintf(L"[+] BasepConstructSxsCreateProcessMessage: 0x%08x\n", Status);
		BaseCreateProcessMessage->PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;

		CsrStringsToCapture[0] = &BaseCreateProcessMessage->Sxs.Win32Path;
		CsrStringsToCapture[1] = &BaseCreateProcessMessage->Sxs.NtPath;
		CsrStringsToCapture[2] = &BaseCreateProcessMessage->Sxs.CacheSxsLanguageBuffer;
		CsrStringsToCapture[3] = &BaseCreateProcessMessage->Sxs.AssemblyIdentity;

		DataLength = sizeof(*BaseCreateProcessMessage);//272 win server 2012
	}
	else if (OSBuildNumber >= 7600)
	{
		wprintf(L"Windows 7 | Windows Server 2008 | Windows Server 2008 R2\n");
		_BasepConstructSxsCreateProcessMessage_2008 BasepConstructSxsCreateProcessMessage_2008 = 0;
		if (BasepConstructSxsCreateProcessMessage_18 == 0)
		{
			wprintf(L"[*] Try wuth FoundStub value: 0x%p\n", BasepConstructSxsCreateProcessMessage_2008_Address);
			BasepConstructSxsCreateProcessMessage_2008 = (_BasepConstructSxsCreateProcessMessage_2008)BasepConstructSxsCreateProcessMessage_2008_Address;
		}
		else
		{
			BasepConstructSxsCreateProcessMessage_2008 = (_BasepConstructSxsCreateProcessMessage_2008)BasepConstructSxsCreateProcessMessage_18;
		}
		Sxs_CreateProcess_UtilityStruct_2008 SxsCreateProcessUtilityStruct_2008 = { 0 };
		RtlSecureZeroMemory(&SxsCreateProcessUtilityStruct_2008, sizeof(SxsCreateProcessUtilityStruct_2008));
		PBASE_CREATEPROCESS_MSG_2012 BaseCreateProcessMessage = &BaseAPIMessage.u.BaseCreateProcess_2012;
		RtlSecureZeroMemory(&BaseCreateProcessMessage->Sxs, sizeof(BaseCreateProcessMessage->Sxs));

		BaseCreateProcessMessage->ProcessHandle = hProcess;
		BaseCreateProcessMessage->ThreadHandle = hThread;
		BaseCreateProcessMessage->ClientId = ClientId;
		BaseCreateProcessMessage->CreationFlags = EXTENDED_STARTUPINFO_PRESENT | IDLE_PRIORITY_CLASS;
		BaseCreateProcessMessage->VdmBinaryType = NULL;
		USHORT SxsCreateFlag = (CreateInfo.InitState.u1.InitFlags & 0x4) != 0;
		USHORT NoIsolation = (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0;
		Status = BasepConstructSxsCreateProcessMessage_2008(
			&NtPath,
			&Win32Path,
			CreateInfo.SuccessState.FileHandle,
			hProcess,
			CreateInfo.SuccessState.SectionHandle,
			FALSE,//AlreadyCheck
			FALSE,//IsRemovableMedia
			(CreateInfo.InitState.u1.InitFlags & 0x4) != 0,
			0,
			0,
			0,
			(DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0,   //No AppX
			(PPEB)CreateInfo.SuccessState.PebAddressNative,
			(PVOID)CreateInfo.SuccessState.ManifestAddress,
			CreateInfo.SuccessState.ManifestSize,
			&CreateInfo.SuccessState.CurrentParameterFlags,
			&BaseCreateProcessMessage->Sxs,
			&SxsCreateProcessUtilityStruct_2008 //472
		);
		wprintf(L"[+] BasepConstructSxsCreateProcessMessage: 0x%08x\n", Status);
		if (!NT_SUCCESS(Status) || BaseCreateProcessMessage->Sxs.Win32Path.Length <= 2)
		{
			wprintf(L"Error?\n");
		}
		BaseCreateProcessMessage->PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;

		CsrStringsToCapture[0] = &BaseCreateProcessMessage->Sxs.Win32Path;
		CsrStringsToCapture[1] = &BaseCreateProcessMessage->Sxs.NtPath;
		CsrStringsToCapture[2] = &BaseCreateProcessMessage->Sxs.CacheSxsLanguageBuffer;
		CsrStringsToCapture[3] = &BaseCreateProcessMessage->Sxs.AssemblyIdentity;
		DataLength = sizeof(*BaseCreateProcessMessage);//272
	
	}
	if (CsrStringsToCapture[0] != NULL)
	{
		wprintf(L"BaseCreateProcessMessage->Sxs.Win32Path: %ls\n", CsrStringsToCapture[0]->Buffer);
		wprintf(L"BaseCreateProcessMessage->Sxs.NtPath: %ls\n", CsrStringsToCapture[1]->Buffer);
		wprintf(L"BaseCreateProcessMessage->Sxs.CacheSxsLanguageBuffer: %ls\n", CsrStringsToCapture[2]->Buffer);
		wprintf(L"BaseCreateProcessMessage->Sxs.AssemblyIdentity: %ls\n", CsrStringsToCapture[3]->Buffer);

		wprintf(L"[+] CsrCaptureMessageMultiUnicodeStringsInPlace: 0x%08x\n", CsrCaptureMessageMultiUnicodeStringsInPlace(&CaptureBuffer, 4, CsrStringsToCapture));
		if (CsrPortHandle && CsrPortMemoryRemoteDelta)
		{
			wprintf(L"[+] Custom CsrClientCallServer\n");
			Status = CsrClientCallServer((PCSR_API_MSG)&BaseAPIMessage, CaptureBuffer, CSRAPINumber, DataLength);
		}
		else
		{
			wprintf(L"[*] Ntdll CsrClientCallServer\n");
			Status = CsrClientCallServer_ntdll((PCSR_API_MSG)&BaseAPIMessage, CaptureBuffer, CSRAPINumber, DataLength);
		}
	}
	else
	{
		Status = 0xc0000005;
	}
	return Status;
}

