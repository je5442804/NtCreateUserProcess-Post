﻿#include "csrss.hpp"
#include "ntapi.hpp"
#include <stdio.h>

// CsrPortHandle and CsrPortMemoryRemoteDelta can be init from CsrpConnectToServer? but we won't do it...  Ovo
NTSTATUS CsrClientCallServer(PCSR_API_MSG ApiMessage, PCSR_CAPTURE_BUFFER  CaptureBuffer, ULONG ApiNumber, ULONG DataLength)
{
	//Without Any SecureCheck is Unsafe but Faster!
	ApiMessage->ApiNumber = ApiNumber & ~0x10000000;
	ApiMessage->h.u2.ZeroInit = 0;

	// ApiMessage->h.u1.Length = (DataLength | (DataLength << 16)) + (((sizeof(CSR_API_MSG) - sizeof(ApiMessage->u)) << 16) | (FIELD_OFFSET(CSR_API_MSG, u) - sizeof(ApiMessage->h)));// +0x400018
	ApiMessage->h.u1.s1.DataLength = (USHORT)DataLength + FIELD_OFFSET(CSR_API_MSG, u) - sizeof(ApiMessage->h);
	ApiMessage->h.u1.s1.TotalLength = (USHORT)DataLength + sizeof(CSR_API_MSG) - sizeof(ApiMessage->u);
	ApiMessage->CaptureBuffer = (PCSR_CAPTURE_BUFFER)((ULONG_PTR)CaptureBuffer + CsrPortMemoryRemoteDelta);
	CaptureBuffer->FreeSpace = 0;//Mark the fact that we are done allocating space from the end of the capture buffer.

	if (NtCurrentPeb()->IsProtectedProcess &&
		CSR_APINUMBER_TO_SERVERDLLINDEX(ApiNumber) == CONSRV_SERVERDLL_INDEX || (ApiNumber & 0x10000000) && !NtCurrentPeb()->IsProtectedProcessLight)
	{
		ApiMessage->ReturnValue = STATUS_ACCESS_DENIED;
		return STATUS_ACCESS_DENIED;
	}

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
	SIZE_T CsrBufferMaxLength = 952;
	NTSTATUS Status = NtAlpcSendWaitReceivePort(//in csrclientcallserver,since win 10 2004 but work well in win 7/2008/2012....
		CsrPortHandle,
		ALPC_MSGFLG_SYNC_REQUEST,
		(PPORT_MESSAGE)ApiMessage,
		0,
		(PPORT_MESSAGE)ApiMessage,
		&CsrBufferMaxLength,// [Optional] 
		0,
		0
	);
	ApiMessage->CaptureBuffer = (PCSR_CAPTURE_BUFFER)((ULONG_PTR)CaptureBuffer - CsrPortMemoryRemoteDelta);
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

void Fastmemcpy(void* dest, void* src, int size)
{
	unsigned char* pdest = (unsigned char*)dest;
	unsigned char* psrc = (unsigned char*)src;
	//Fast 4 bytes->1 byte 
	int loops = (size / sizeof(ULONG));
	for (int index = 0; index < loops; ++index)
	{
		*((ULONG*)pdest) = *((ULONG*)psrc);
		pdest += sizeof(ULONG);
		psrc += sizeof(ULONG);
	}

	loops = (size % sizeof(ULONG));
	for (int index = 0; index < loops; ++index)
	{
		*pdest = *psrc;
		++pdest;
		++psrc;
	}
}

ULONG CsrAllocateMessagePointer(PCSR_CAPTURE_BUFFER CaptureBuffer, ULONG Length, PVOID* Pointer)
{
	if (Length == 0) {
		*Pointer = NULL;
		Pointer = NULL;
	}
	else {
		*Pointer = CaptureBuffer->FreeSpace;
		if (Length >= MAXLONG) {
			return 0;
		}
		Length = (Length + 3) & ~3;
		CaptureBuffer->FreeSpace += Length;
	}
	CaptureBuffer->MessagePointerOffsets[CaptureBuffer->CountMessagePointers++] = (ULONG_PTR)Pointer;
	return Length;
}

void CsrCaptureMessageString(PCSR_CAPTURE_BUFFER CaptureBuffer, PWSTR String, ULONG Length, ULONG MaximumLength, PUNICODE_STRING CapturedString)
{
	CapturedString->Length = (USHORT)Length;
	CapturedString->MaximumLength = (USHORT)CsrAllocateMessagePointer(CaptureBuffer, MaximumLength, (PVOID*)&CapturedString->Buffer);
	Fastmemcpy(CapturedString->Buffer, String, MaximumLength);
}

NTSTATUS CsrCaptureMessageMultiUnicodeStringsInPlace(PCSR_CAPTURE_BUFFER* InOutCaptureBuffer, ULONG NumberOfStringsToCapture, const PUNICODE_STRING* StringsToCapture)
{
	ULONG Length = 0;
	if (!InOutCaptureBuffer || !NumberOfStringsToCapture)
		return STATUS_INVALID_PARAMETER;
	PCSR_CAPTURE_BUFFER CaptureBuffer = *InOutCaptureBuffer;
	if (CaptureBuffer == NULL)
	{
		for (int i = 0; i != NumberOfStringsToCapture; ++i) {
			if (StringsToCapture[i] != NULL) {
				Length += StringsToCapture[i]->MaximumLength;
			}
		}
		//CsrAllocateCaptureBuffer
		Length += FIELD_OFFSET(CSR_CAPTURE_BUFFER, MessagePointerOffsets) + (NumberOfStringsToCapture * sizeof(PVOID));//32 is the [MessagePointerOffsets] FIELD_OFFSET 
		Length = (Length + (3 * (NumberOfStringsToCapture + 1))) & ~3;
		if (Length >= MAXLONG)//Post btter
			return STATUS_INVALID_PARAMETER;
		
		//wprintf(L"(char)NtCurrentPeb()->ReadOnlyStaticServerData-(char*)NtCurrentPeb()->ReadOnlySharedMemoryBase = 0x%08x\n", (char*)NtCurrentPeb()->ReadOnlyStaticServerData - (NtCurrentPeb()->ReadOnlySharedMemoryBase));
		CaptureBuffer = (PCSR_CAPTURE_BUFFER)((ULONG_PTR)CsrPortHeap + ((ULONG_PTR)NtCurrentPeb()->ReadOnlyStaticServerData - (ULONG_PTR)NtCurrentPeb()->ReadOnlySharedMemoryBase));//Thank you!
		
		if (!CaptureBuffer)
			return STATUS_NO_MEMORY;

		wprintf(L"[+] CaptureBuffer FakeAlloc = 0x%p\n", CaptureBuffer);

		CaptureBuffer->Length = Length;
		CaptureBuffer->CountMessagePointers = 0;
		CaptureBuffer->FreeSpace = (char*)CaptureBuffer->MessagePointerOffsets + NumberOfStringsToCapture * sizeof(ULONG_PTR);
		*InOutCaptureBuffer = CaptureBuffer;
	}
	for (int i = 0; i != NumberOfStringsToCapture && StringsToCapture[i] != NULL; ++i) {
		CsrCaptureMessageString(
			CaptureBuffer,
			StringsToCapture[i]->Buffer,
			StringsToCapture[i]->Length,
			StringsToCapture[i]->MaximumLength,
			StringsToCapture[i]
		);
		if (StringsToCapture[i]->MaximumLength > StringsToCapture[i]->Length && (StringsToCapture[i]->MaximumLength - StringsToCapture[i]->Length) >= sizeof(WCHAR)) {
			StringsToCapture[i]->Buffer[StringsToCapture[i]->Length / sizeof(WCHAR)] = 0;
		}
	}
	return 0;
}

NTSTATUS CallCsrss(HANDLE hProcess, HANDLE hThread, PS_CREATE_INFO CreateInfo, UNICODE_STRING Win32ImagePath, UNICODE_STRING NtImagePath, CLIENT_ID ClientId, SECTION_IMAGE_INFORMATION SectionImageInfomation)
{
	NTSTATUS Status = NULL;
	PCSR_CAPTURE_BUFFER CaptureBuffer = 0;
	BASE_API_MSG BaseAPIMessage = { 0 };
	PBASE_CREATEPROCESS_MSG BaseCreateProcessMessage = &BaseAPIMessage.u.BaseCreateProcess;
	PUNICODE_STRING CsrStringsToCapture[6] = { 0 };
	CSR_API_NUMBER CSRAPINumber = CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess);
	ULONG DataLength = 0;
	UNICODE_STRING CultureFallBacks = { 0 };
	UNICODE_STRING AssemblyName = { 0 };
	USHORT ImageProcessorArchitecture = 0;
	ULONG RtlUserProcessParametersFlags = RTL_USER_PROC_IMAGE_KEY_MISSING | RTL_USER_PROC_APP_MANIFEST_PRESENT | RTL_USER_PROC_PARAMS_NORMALIZED;

	switch (SectionImageInfomation.Machine)
	{
	case IMAGE_FILE_MACHINE_I386:
		//If this is a .NET ILONLY that needs to run in a 64-bit addressspace, then let SXS be aware of this
		if (CreateInfo.SuccessState.u2.s2.AddressSpaceOverride)
			ImageProcessorArchitecture = SharedUserData->NativeProcessorArchitecture;
		else
			ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_IA32_ON_WIN64;
		break;
	case IMAGE_FILE_MACHINE_ARMNT:
		ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM;
		break;
	case IMAGE_FILE_MACHINE_HYBRID_X86:
		ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_IA32_ON_WIN64;
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
		break;
	case IMAGE_FILE_MACHINE_ARM64:
		ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64;
		break;
	default:
		wprintf(L"[*] Kernel32: No mapping for ImageInformation.Machine == %04x\n", SectionImageInfomation.Machine);//DbgPrint_0
		ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_UNKNOWN;
		break;
	}

	// Weird L":" auto appended behind 2 bytes L"zh-CN\0zh-Hans\0zh\0en-US\0en" in LLVM (e.n...:.)
	CultureFallBacks.Buffer = (PWSTR)L"zh-CN\0zh-Hans\0zh\0en-US\0en\0"; // zh-CN en-US
	CultureFallBacks.Length = 54;//8?
	CultureFallBacks.MaximumLength = 54;//8

	AssemblyName.Buffer = (PWSTR)L"-----------------------------------------------------------";
	AssemblyName.Length = 118;
	AssemblyName.MaximumLength = 120;

	BaseCreateProcessMessage->ProcessHandle = hProcess;
	BaseCreateProcessMessage->ThreadHandle = hThread;
	BaseCreateProcessMessage->ClientId = ClientId;
	BaseCreateProcessMessage->CreationFlags = 0;
	BaseCreateProcessMessage->VdmBinaryType = NULL;

	wprintf(L"[*] OS: %d\n", OSBuildNumber);
	wprintf(L"============================================================================================\n");
	
	if (OSBuildNumber >= 18985)//19041 ? 19000
	{
		wprintf(L"[*] Windows 10 2004+ | Windows 11+ | Windows Server 2022+\n");
		CustomSecureZeroMemory(&BaseCreateProcessMessage->u.win2022.Sxs, sizeof((BaseCreateProcessMessage->u).win2022.Sxs));
		BaseCreateProcessMessage->u.win2022.Sxs.FileHandle = CreateInfo.SuccessState.FileHandle;
		BaseCreateProcessMessage->u.win2022.Sxs.ManifestAddress = (PVOID)CreateInfo.SuccessState.ManifestAddress;
		BaseCreateProcessMessage->u.win2022.Sxs.ManifestSize = CreateInfo.SuccessState.ManifestSize;
		BaseCreateProcessMessage->u.win2022.Sxs.Flags = BASE_MSG_SXS_ALTERNATIVE_MODE;
		BaseCreateProcessMessage->u.win2022.Sxs.ProcessParameterFlags = RtlUserProcessParametersFlags;
		BaseCreateProcessMessage->u.win2022.PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->u.win2022.PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->u.win2022.ProcessorArchitecture = ImageProcessorArchitecture;
		CsrStringsToCapture[0] = &(BaseCreateProcessMessage->u.win2022.Sxs.Win32ImagePath = Win32ImagePath);
		CsrStringsToCapture[1] = &(BaseCreateProcessMessage->u.win2022.Sxs.NtImagePath = NtImagePath);
		CsrStringsToCapture[2] = &(BaseCreateProcessMessage->u.win2022.Sxs.CultureFallBacks = CultureFallBacks);
		CsrStringsToCapture[3] = &(BaseCreateProcessMessage->u.win2022.Sxs.AssemblyName = AssemblyName);

		CSRAPINumber = CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess2);//since 2004
		DataLength = sizeof(*BaseCreateProcessMessage);//536 = 456(0x1c8) + 80 
	}
	else if (OSBuildNumber >= 18214 || (OSBuildNumber <= 9600 && OSBuildNumber >= 8423) || (OSBuildNumber <= 7601 && OSBuildNumber >= 7600))//18362 | 9200
	{
		wprintf(L"[*] Windows 10 1903 | Windows 10 1909\n");
		wprintf(L"[*] Windows 8 | Windows 8.1 | Windows Server 2012 | Windows Server 2012 R2\n");
		wprintf(L"[*] Windows 7 | Windows Server 2008 R2\n");
		CustomSecureZeroMemory(&BaseCreateProcessMessage->u.win2012.Sxs, sizeof((BaseCreateProcessMessage->u).win2012.Sxs));
		BaseCreateProcessMessage->u.win2012.Sxs.FileHandle = CreateInfo.SuccessState.FileHandle;
		BaseCreateProcessMessage->u.win2012.Sxs.ManifestAddress = (PVOID)CreateInfo.SuccessState.ManifestAddress;
		BaseCreateProcessMessage->u.win2012.Sxs.ManifestSize = CreateInfo.SuccessState.ManifestSize;
		BaseCreateProcessMessage->u.win2012.Sxs.Flags = BASE_MSG_SXS_ALTERNATIVE_MODE;
		BaseCreateProcessMessage->u.win2012.Sxs.ProcessParameterFlags = RtlUserProcessParametersFlags;
		BaseCreateProcessMessage->u.win2012.PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->u.win2012.PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->u.win2012.ProcessorArchitecture = ImageProcessorArchitecture;
		CsrStringsToCapture[0] = &(BaseCreateProcessMessage->u.win2012.Sxs.Win32ImagePath = Win32ImagePath);
		CsrStringsToCapture[1] = &(BaseCreateProcessMessage->u.win2012.Sxs.NtImagePath = NtImagePath);
		CsrStringsToCapture[2] = &(BaseCreateProcessMessage->u.win2012.Sxs.CultureFallBacks = CultureFallBacks);
		CsrStringsToCapture[3] = &(BaseCreateProcessMessage->u.win2012.Sxs.AssemblyName = AssemblyName);

		DataLength = sizeof((BaseCreateProcessMessage->u).win2012.Sxs) + 80;//272 = 192 + 80
	}
	else if (OSBuildNumber >= 6000)
	{
		wprintf(L"[*] Windows 10 1803 | Windows 10 1809 | Windows Server 2019\n");
		wprintf(L"[*] Windows 10 1703 | Windows 10 1709\n");
		wprintf(L"[*] Windows 10 1507 | Windows 10 1511 | Windows 10 1607 | Windows Server 2016\n");
		wprintf(L"[*] Windows  Vista  | Windows Server 2008\n");
		CustomSecureZeroMemory(&BaseCreateProcessMessage->u.win2016.Sxs, sizeof((BaseCreateProcessMessage->u).win2016.Sxs));
		BaseCreateProcessMessage->u.win2016.Sxs.FileHandle = CreateInfo.SuccessState.FileHandle;
		BaseCreateProcessMessage->u.win2016.Sxs.ManifestAddress = (PVOID)CreateInfo.SuccessState.ManifestAddress;
		BaseCreateProcessMessage->u.win2016.Sxs.ManifestSize = CreateInfo.SuccessState.ManifestSize;
		BaseCreateProcessMessage->u.win2016.Sxs.Flags = BASE_MSG_SXS_ALTERNATIVE_MODE;
		BaseCreateProcessMessage->u.win2016.Sxs.ProcessParameterFlags = RtlUserProcessParametersFlags;
		BaseCreateProcessMessage->u.win2016.PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->u.win2016.PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->u.win2016.ProcessorArchitecture = ImageProcessorArchitecture;
		CsrStringsToCapture[0] = &(BaseCreateProcessMessage->u.win2016.Sxs.Win32ImagePath = Win32ImagePath);
		CsrStringsToCapture[1] = &(BaseCreateProcessMessage->u.win2016.Sxs.NtImagePath = NtImagePath);
		CsrStringsToCapture[2] = &(BaseCreateProcessMessage->u.win2016.Sxs.CultureFallBacks = CultureFallBacks);
		CsrStringsToCapture[3] = &(BaseCreateProcessMessage->u.win2016.Sxs.AssemblyName = AssemblyName);

		DataLength = sizeof((BaseCreateProcessMessage->u).win2016.Sxs) + 80;//264 = 184 + 80
	}
	else
	{
		wprintf(L"[-] Unknow OSBuildNumber or it isn't supported.\n");
		return STATUS_NOT_SUPPORTED;
	}

	if (CsrStringsToCapture[0]->Length != 0)
	{
		wprintf(L"BaseCreateProcessMessage->Sxs.Win32ImagePath: %ls\n", CsrStringsToCapture[0]->Buffer);
		wprintf(L"BaseCreateProcessMessage->Sxs.NtImagePath: %ls\n", CsrStringsToCapture[1]->Buffer);
		wprintf(L"BaseCreateProcessMessage->Sxs.CultureFallBacks: ");
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), CsrStringsToCapture[2]->Buffer, CsrStringsToCapture[2]->Length / 2, NULL, 0);
		wprintf(L"\nBaseCreateProcessMessage->Sxs.AssemblyName: %ls\n", CsrStringsToCapture[3]->Buffer);

		//DbgPrint( "*** CSRSS: CaptureBuffer outside of ClientView\n" );
		//CaptureBuffer should in ClientView [CsrPortHeap] or return STATUS_INVALID_PARAMETER(0xC000000D)
		wprintf(L"[+] CsrCaptureMessageMultiUnicodeStringsInPlace: 0x%08x\n", CsrCaptureMessageMultiUnicodeStringsInPlace(&CaptureBuffer, 4, CsrStringsToCapture));
		return CsrClientCallServer((PCSR_API_MSG)&BaseAPIMessage, CaptureBuffer, CSRAPINumber, DataLength);
	}
	else
	{
		return STATUS_ACCESS_VIOLATION;
	}
}