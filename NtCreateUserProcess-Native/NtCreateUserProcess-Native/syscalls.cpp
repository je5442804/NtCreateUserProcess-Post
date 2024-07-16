#include "syscalls.hpp"
#include "ntapi.hpp"
#include <stdio.h>
#include <intrin.h>

#define JUMPER

const static BYTE signaturecode[] = { 0x00, 0x48, 0x85, 0xc9, 0x48, 0x89, 0x35 };//0x75 0x07, 0xeb, 0x0a
SW3_SYSCALL_LIST SW3_SyscallList = { 0 };
PVOID CsrPortHeap = 0;
HANDLE CsrPortHandle = NULL;
ULONG_PTR CsrPortMemoryRemoteDelta = 0;
USHORT OSBuildNumber = 0;
HANDLE ConhostConsoleHandle = NULL;
RtlAllocateHeap_ RtlAllocateHeap;
const static BYTE signaturecode2[] = { 0x48, 0x89, 0x05, 0x00, 0xe8, 0x00, 0x4c, 0x8b, 0x45, 0x00, 0x4c, 0x8b, 0x84, 0x24 };


ULONG_PTR SW3_HashSyscall(PCSTR FunctionName)
{
	DWORD i = 0;
	ULONG_PTR Hash = SW3_SEED;

	while (FunctionName[i])
	{
		WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
		Hash ^= (ULONG_PTR)PartialName * SW3_ROR8(Hash);
		Hash *= 2;
	}

	return Hash;
}

PVOID SC_Address(PVOID NtApiAddress)
{
	DWORD searchLimit = 520;
	PVOID SyscallAddress;
	BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
	ULONG distance_to_syscall = 0x12;
	if (OSBuildNumber != 0 && OSBuildNumber < 10586) //Beta 10525
	{
		distance_to_syscall = 0x08;
	}
	// we don't really care if there is a 'jmp' between
	// NtApiAddress and the 'syscall; ret' instructions
	SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

	if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
	{
		// we can use the original code for this system call :)
		return SyscallAddress;
	}
	// the 'syscall; ret' intructions have not been found,
	// we will try to use one near it, similarly to HalosGate
	for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
	{
		// let's try with an Nt* API below our syscall
		SyscallAddress = SW3_RVA2VA(
			PVOID,
			NtApiAddress,
			distance_to_syscall + num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		{
			return SyscallAddress;
		}

		// let's try with an Nt* API above our syscall
		SyscallAddress = SW3_RVA2VA(
			PVOID,
			NtApiAddress,
			distance_to_syscall - num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		{
			return SyscallAddress;
		}
	}
	return NULL;
}

int GetGlobalVariable(PVOID Ntdll, DWORD SizeOfNtdll, PVOID KernelBase, DWORD SizeofKernelBase)
{
	//48 8B 4C 24 50 这个也可以?
	SizeOfNtdll -= 0x100;
	const static BYTE signaturecode3[] = { 0xb9, 0x00, 0x80, 0x00, 0x00 };

	//Try to evade use HeapAlloc|RtlAllocHeap,however this way is really unsafe & dangerous...
		//Well, we are likely on the razor's edge..... 游走于刀尖之上...
		//What if CaptureBuffer to Allocated is bigger than excepted, try to alloc new memroy? 
		//How to get CsrPortHeap Address?
		//1: A HeapMemroy ID=2 ,type = Mapped:Commited, BaseAddress < NtCurrentPeb()->ProcessHeap(EZ)
		//2: find with signcode 
	CsrPortHeap = *(PVOID*)((ULONG_PTR)(NtCurrentPeb()->ProcessHeaps) + 8);//id = 2,so the second heap is +8

	// mov r8, ...
	// 4C 8B 84 24
	// 4C 8B 45
	PVOID tempaddress = 0;
	DWORD i = 0;
	DWORD addresscount = 2;
	for (i = 0; i < SizeOfNtdll && addresscount; i++)
	{
		tempaddress = (char*)Ntdll + i;
		if (!memcmp(signaturecode, tempaddress, 4)
			&& memcmp(signaturecode, (char*)tempaddress - 1, 1)
			&& memcmp(signaturecode, (char*)tempaddress - 2, 1) //Badsense: memcmp(signaturecode, (char*)tempaddress - 2(or 3), 1)
			&& !memcmp((char*)signaturecode + 4, (char*)tempaddress - 6, 3))
		{
			//wprintf(L"found: 0x%p\n", tempaddress);
			if (!CsrPortHeap)
			{
				// Windows 11 24H2 Insider
				PVOID x = (char*)tempaddress;
				for (int j = 0; j <= 0x80; j++)
				{
					if (!memcmp(signaturecode3, (char*)x - j, 5))
					{
						x = (char*)x - j + 5;
						for (int z = 0; z <= 0x40; z++)
						{
							if (!memcmp(signaturecode2, (char*)x + z, 3))
							{
								x = (char*)x + z + 3;
								PVOID CsrPortHeapAddress = (char*)x + 4 + *(DWORD*)x;
								CsrPortHeap = *(PVOID*)CsrPortHeapAddress;
								break;
							}
						}
						break;
					}
				}
				
			}
			PVOID CsrPortHandleAddress = ((char*)tempaddress + 1) + *((DWORD*)((__int64)tempaddress - 3));
			//wprintf(L"[+] Get CsrPortHandle Address: 0x%p\n", CsrPortHandleAddress);
			CsrPortHandle = *(PVOID*)CsrPortHandleAddress;
			wprintf(L"[+] CsrPortHandle: 0x%p\n", CsrPortHandle);
			addresscount--;
		}

		if (!memcmp(signaturecode2, tempaddress, 3)
			&& !memcmp((char*)signaturecode2 + 3, (char*)tempaddress + 6, 2)
			&& (!memcmp((char*)signaturecode2 + 5, (char*)tempaddress + 11, 4) || !memcmp((char*)signaturecode2 + 9, (char*)tempaddress + 11, 5)))
		{
			//wprintf(L"found: 0x%p\n", tempaddress);
			tempaddress = (char*)tempaddress + 3;
			//wprintf(L"tempaddress= %p\n", tempaddress);
			//wprintf(L"hex test2 RSVA: %p\n", (PVOID) * ((DWORD*)(tempaddress)));
			PVOID CsrPortMemoryRemoteDeltaAddress = (char*)tempaddress + 4 + *((DWORD*)(tempaddress));
			//wprintf(L"[+] Get CsrPortMemoryRemoteDelta Address: 0x%p\n", CsrPortMemoryRemoteDeltaAddress);
			CsrPortMemoryRemoteDelta = *(ULONG_PTR*)CsrPortMemoryRemoteDeltaAddress;
			
			wprintf(L"[+] CsrPortMemoryRemoteDelta: 0x%p\n", (PVOID)CsrPortMemoryRemoteDelta);
			addresscount--;
		}
	}	

	//find consolehandle
		/*
		typedef _CONSOLE_INFO{
			ULONGLONG ConsoleConnectionState;//0 <---  PS_STD_* likly
			HANDLE CurrentConsoleHandle;//8
			HANDLE ConhostConsoleHandle;//16 <-- This one!
			HANDLE StandardInput;/24
			HANDLE StandardOutput;//32
			HANDLE StandardError;//40
			BOOLEAN CreateConsoleSuccess;//48
		}CONSOLE_INFO, *PCONSOLE_INFO;//56
	*/

	if (OSBuildNumber > 7601 && KernelBase)
	{
		PVOID FreeConsoleAddress = (PVOID)GetProcAddress((HMODULE)KernelBase, "FreeConsole");
		//BYTE signaturecode3[] = { 0xB9,0x58,0x02,0x00,0x00,0x66,0x3B,0xC1 };
		BYTE signaturecode3[] = { 0x48, 0x8D, 0x0D };
		for (int i = 0; i < 0x100; i++)
		{
			tempaddress = (char*)FreeConsoleAddress + i;
			if (*(BYTE*)((char*)tempaddress + 7) == 0xE8 && !memcmp(signaturecode3, tempaddress, 3))
			{
				tempaddress = (char*)tempaddress + 3;
				PVOID ConhostConsoleHandleAddress = (char*)tempaddress + 4 + *((DWORD*)(tempaddress)) + 0x10;
				//wprintf(L"[+] Get ConhostConsoleHandleAddress Address: 0x%p\n", ConhostConsoleHandleAddress);
				ConhostConsoleHandle = *(HANDLE*)ConhostConsoleHandleAddress;

				
				break;
			}
		}
		
	}

	wprintf(L"[+] CsrPortHeap: 0x%p\n", CsrPortHeap);
	wprintf(L"[+] ConhostConsoleHandle: 0x%p\n", (PVOID)ConhostConsoleHandle);

	return 0;
}

BOOL SW3_PopulateSyscallList()
{
	// Return early if the list is already populated.
	if (SW3_SyscallList.Entries[0].Address)
		return TRUE;
	
	PSW3_PEB_LDR_DATA Ldr = NtCurrentPeb()->Ldr;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectoryNtdll = NULL;
	PVOID DllBase = NULL;
	// Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
	// in the list, so it's safer to loop through the full list and find it.
	PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
	PVOID Ntdll = 0;
	DWORD SizeOfNtdll = 0;
	PVOID KernelBase = 0;
	DWORD SizeofKernelBase = 0;
	for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
	{
		DllBase = LdrEntry->DllBase;
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
		PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
		PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;

		DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (VirtualAddress == 0) continue;

		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
		// If this is NTDLL.dll, exit loop.
		PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

		if ((*(ULONG*)DllName | 0x20202020) == 'nrek' && (*(ULONG*)(DllName + 4) | 0x20202020) == 'able')
		{
			wprintf(L"[+] KernelBase: 0x%p\n", DllBase);
			KernelBase = DllBase;
			SizeofKernelBase = NtHeaders->OptionalHeader.SizeOfImage;
		}
		if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
		if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c)
		{
			wprintf(L"[+] NtdllBase: 0x%p\n", DllBase);
			Ntdll = DllBase;
			SizeOfNtdll = NtHeaders->OptionalHeader.SizeOfImage;
			ExportDirectoryNtdll = ExportDirectory;
		}
		if (Ntdll && KernelBase)
			break;
		DllBase = 0;
	}
	if (!ExportDirectoryNtdll || !Ntdll)
		return FALSE;
	OSBuildNumber = NtCurrentPeb()->OSBuildNumber;
	RtlAllocateHeap = (RtlAllocateHeap_)GetProcAddress((HMODULE)Ntdll, "RtlAllocateHeap");

	GetGlobalVariable(Ntdll, SizeOfNtdll, KernelBase, SizeofKernelBase);

	DWORD NumberOfNames = ExportDirectoryNtdll->NumberOfNames;

	PDWORD Functions = SW3_RVA2VA(PDWORD, Ntdll, ExportDirectoryNtdll->AddressOfFunctions);
	PDWORD Names = SW3_RVA2VA(PDWORD, Ntdll, ExportDirectoryNtdll->AddressOfNames);
	PWORD Ordinals = SW3_RVA2VA(PWORD, Ntdll, ExportDirectoryNtdll->AddressOfNameOrdinals);

	// Populate SW3_SyscallList with unsorted Zw* entries.
	DWORD i = 0;
	PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;

	do
	{
		PCHAR FunctionName = SW3_RVA2VA(PCHAR, Ntdll, Names[NumberOfNames - 1]);

		// Is this a system call?
		if (*(USHORT*)FunctionName == 0x775a)
		{
			Entries[i].Hash = SW3_HashSyscall(FunctionName);
			Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
			Entries[i].SyscallAddress = (PVOID)((ULONG_PTR)SC_Address(SW3_RVA2VA(PVOID, Ntdll, Entries[i].Address)) << (Entries[i].Hash % 8));

			i++;
			if (i == SW3_MAX_ENTRIES) break;
		}
	} while (--NumberOfNames);

	// Save total number of system calls found.
	SW3_SyscallList.Count = i;

	// Sort the list by address in ascending order.
	for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
	{
		for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
		{
			if (Entries[j].Address > Entries[j + 1].Address)
			{
				// Swap entries.
				SW3_SYSCALL_ENTRY TempEntry;

				TempEntry.Hash = Entries[j].Hash;
				TempEntry.Address = Entries[j].Address;
				TempEntry.SyscallAddress = Entries[j].SyscallAddress;

				Entries[j].Hash = Entries[j + 1].Hash;
				Entries[j].Address = Entries[j + 1].Address;
				Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

				Entries[j + 1].Hash = TempEntry.Hash;
				Entries[j + 1].Address = TempEntry.Address;
				Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
			}
		}
	}
	for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
	{
		Entries[i].Address = Entries[i].Hash * (DWORD)Entries[i].SyscallAddress << i;
	}

	return TRUE;
}

EXTERN_C ULONG_PTR ABCDEFG(float a1, float a2, float a3, float a4, ULONG_PTR FunctionHash, PVOID* lpSyscallAddress)
{
	if (!SW3_PopulateSyscallList())
		return 0;
	
	ULONG Index = ((ULONG_PTR)lpSyscallAddress | (ULONG_PTR)&FunctionHash * FunctionHash + (ULONG_PTR)(a1 + a2 + a3 + a4)) % SW3_SyscallList.Count;
	*lpSyscallAddress = (PVOID)((ULONG_PTR)SW3_SyscallList.Entries[Index].SyscallAddress >> (SW3_SyscallList.Entries[Index].Hash % 8));

	for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
	{
		if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
		{
			return i|(((ULONG_PTR)&i * FunctionHash) << 32);
		}
	}
	a1 = a2 - a3;

	return a1*a3+ (a2 / (a1+a2+a3+a4)); //| a3 * a4;
}