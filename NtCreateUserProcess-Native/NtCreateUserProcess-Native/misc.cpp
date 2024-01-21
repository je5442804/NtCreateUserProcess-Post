#include "misc.hpp"
#include <stdio.h>

void CustomSecureZeroMemory(IN OUT PVOID ptr, IN SIZE_T cnt)
{
	volatile char* force;
	force = (volatile char*)ptr;
	while (cnt)
	{
		*force++ = 0;
		cnt--;
	}
}

ULONG GetProcessParametersStructsLength(USHORT BuildNumber)
{
	ULONG ProcessParametersLength = 0;
	if (BuildNumber > 22000)
	{
		ProcessParametersLength = sizeof(RTL_USER_PROCESS_PARAMETERS);// 0x448 1096
	}
	else if (BuildNumber > 17763 && BuildNumber <= 22000)
	{
		ProcessParametersLength = 0x440;// 1088
	}
	else if (BuildNumber > 16299 && BuildNumber <= 17763)
	{
		ProcessParametersLength = 0x420;
	}
	else if (BuildNumber > 7601 && BuildNumber <= 16299)
	{
		ProcessParametersLength = 0x410;
	}
	else if (BuildNumber >= 7600 && BuildNumber <= 7601)
	{
		ProcessParametersLength = 0x400;
	}
	else if (BuildNumber >= 6000 && BuildNumber < 7600)
	{
		ProcessParametersLength = 0x3F8;//1016
	}
	wprintf(L"[+] OS: %d, ProcessParametersLength = 0x%x\n", BuildNumber, ProcessParametersLength);
	return ProcessParametersLength;
}
void CreateInfoOutPut(PS_CREATE_INFO CreateInfo)
{

	wprintf(L"CreateInfo.InitFlags: 0x%08x\n", CreateInfo.InitState.u1.InitFlags);
	wprintf(L"CreateInfo.WriteOutputOnExit: 0x%08x\n", CreateInfo.InitState.u1.s1.WriteOutputOnExit);
	wprintf(L"CreateInfo.DetectManifest: 0x%08x\n", CreateInfo.InitState.u1.s1.DetectManifest);
	wprintf(L"CreateInfo.IFEOSkipDebugger: 0x%08x\n", CreateInfo.InitState.u1.s1.IFEOSkipDebugger);
	wprintf(L"CreateInfo.IFEODoNotPropagateKeyState: 0x%08x\n", CreateInfo.InitState.u1.s1.IFEODoNotPropagateKeyState);
	//wprintf(L"CreateInfo.SpareBits1: 0x%08x\n", CreateInfo.InitState.u1.s1.SpareBits1);
	//wprintf(L"CreateInfo.SpareBits2: 0x%08x\n", CreateInfo.InitState.u1.s1.SpareBits2);
	wprintf(L"CreateInfo.ProhibitedImageCharacteristics: 0x%08x\n", CreateInfo.InitState.u1.s1.ProhibitedImageCharacteristics);
	wprintf(L"============================================================================================\n");
	wprintf(L"CreateInfo.OutputFlags: 0x%x\n", CreateInfo.SuccessState.u2.OutputFlags);
	wprintf(L"CreateInfo.ProtectedProcess: %d\n", CreateInfo.SuccessState.u2.s2.ProtectedProcess);
	wprintf(L"CreateInfo.ProtectedProcessLight: %d\n", CreateInfo.SuccessState.u2.s2.ProtectedProcessLight);
	wprintf(L"CreateInfo.AddressSpaceOverride: %d\n", CreateInfo.SuccessState.u2.s2.AddressSpaceOverride);
	wprintf(L"CreateInfo.DevOverrideEnabled: %d\n", CreateInfo.SuccessState.u2.s2.DevOverrideEnabled);
	wprintf(L"CreateInfo.ManifestDetected: %d\n", CreateInfo.SuccessState.u2.s2.ManifestDetected);
	//wprintf(L"CreateInfo.SpareBits1: 0x%03x\n", CreateInfo.SuccessState.u2.s2.SpareBits1);
	//wprintf(L"CreateInfo.SpareBits2: 0x%08x\n", CreateInfo.SuccessState.u2.s2.SpareBits2);
	//wprintf(L"CreateInfo.SpareBits3: 0x%08x\n", CreateInfo.SuccessState.u2.s2.SpareBits3);
	wprintf(L"--------------------------------------------------------------------------------------------\n");
	wprintf(L"CreateInfo.FileHandle:0x%p\n", CreateInfo.SuccessState.FileHandle);
	wprintf(L"CreateInfo.SectionHandle: 0x%p\n", CreateInfo.SuccessState.SectionHandle);
	wprintf(L"CreateInfo.UserProcessParametersNative: 0x%p\n", (PVOID)CreateInfo.SuccessState.UserProcessParametersNative);
	wprintf(L"CreateInfo.CurrentParameterFlags: 0x%08x\n", CreateInfo.SuccessState.CurrentParameterFlags);
	wprintf(L"CreateInfo.PebAddressNative: 0x%p\n", (PVOID)CreateInfo.SuccessState.PebAddressNative);
	wprintf(L"CreateInfo.ManifestAddress: 0x%p\n", (PVOID)CreateInfo.SuccessState.ManifestAddress);
	wprintf(L"CreateInfo.ManifestSize: %d\n", CreateInfo.SuccessState.ManifestSize);
	wprintf(L"--------------------------------------------------------------------------------------------\n");
	wprintf(L"CreateInfo.ExeFormat.DllCharacteristics: 0x%08x\n", CreateInfo.ExeFormat.DllCharacteristics);
	//IMAGE_FILE_EXECUTABLE_IMAGE
	wprintf(L"============================================================================================\n");
}
void SectionImageInfomationOutPut(SECTION_IMAGE_INFORMATION SectionImageInfomation)
{
	wprintf(L"ImageInformation.Machine: 0x%x\n", SectionImageInfomation.Machine);//PROCESSOR_ARCHITECTURE_AMD64 - IMAGE_FILE_MACHINE_AMD64
	wprintf(L"ImageInformation.SubSystemType: %d\n", SectionImageInfomation.SubSystemType);
	wprintf(L"ImageInformation.SubSystemMinorVersion: %d\n", SectionImageInfomation.SubSystemMinorVersion);
	wprintf(L"ImageInformation.SubSystemMajorVersion: %d\n", SectionImageInfomation.SubSystemMajorVersion);
	wprintf(L"ImageInformation.SubSystemVersion: %d\n", SectionImageInfomation.SubSystemVersion);
	wprintf(L"ImageInformation.MajorOperatingSystemVersion: %d\n", SectionImageInfomation.MajorOperatingSystemVersion);
	wprintf(L"ImageInformation.MinorOperatingSystemVersion: %d\n", SectionImageInfomation.MinorOperatingSystemVersion);
	wprintf(L"ImageInformation.OperatingSystemVersion: %d\n", SectionImageInfomation.OperatingSystemVersion);
	wprintf(L"ImageInformation.ImageFileSize: %d\n", SectionImageInfomation.ImageFileSize);
	wprintf(L"ImageInformation.TransferAddress: 0x%p\n", SectionImageInfomation.TransferAddress);
	wprintf(L"ImageInformation.LoaderFlags: %d\n", SectionImageInfomation.LoaderFlags);
	wprintf(L"ImageInformation.DllCharacteristics: 0x%08x\n", SectionImageInfomation.DllCharacteristics);
	wprintf(L"============================================================================================\n");
}
