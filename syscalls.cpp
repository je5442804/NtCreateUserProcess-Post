#include "syscalls.hpp"
#include <stdio.h>

#define JUMPER
SW3_SYSCALL_LIST SW3_SyscallList;
HANDLE CsrPortHandle;
ULONG_PTR CsrPortMemoryRemoteDelta;
USHORT OSBuildNumber;
PVOID BasepConstructSxsCreateProcessMessage_2008_Address;

DWORD SW3_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW3_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW3_ROR8(Hash);
    }

    return Hash;
}

PVOID SC_Address(PVOID NtApiAddress)
{
    DWORD searchLimit = 512;
    PVOID SyscallAddress;
    BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
    ULONG distance_to_syscall = 0x12;
    if (OSBuildNumber !=0 && OSBuildNumber < 10586) //Beta 10525
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

int GetCsrPortHandle(PVOID DllBase, DWORD SizeOfNtdll)
{
    //48 8B 4C 24 50 这个也可以?
    
    BYTE signaturecode[] = {0x00,0x48,0x85,0xc9,0x48,0x89,0x35};//0x75 0x07, 0xeb, 0x0a
    PVOID tempaddress = 0;
    int i = 0;
    for (i = 0; i < SizeOfNtdll; i++)
    {
        tempaddress = (char*)DllBase + i;
        if (!memcmp(signaturecode, tempaddress, sizeof(signaturecode)*0.5) 
            && memcmp(signaturecode, (char*)tempaddress - 1, 1) 
            && memcmp(signaturecode, (char*)tempaddress - 2, 1) //Badsense: memcmp(signaturecode, (char*)tempaddress - 2(or 3), 1)
            && !memcmp((char*)signaturecode+4, (char*)tempaddress - 6, 3))
        {
            //wprintf(L"found: 0x%p\n", tempaddress);
            break;
        }       
    }

    if (i == SizeOfNtdll)
    {
        wprintf(L"[-] No Found CsrPortHandle\n");
        CsrPortHandle = 0;
        return -1;
    }
    //wprintf(L"the next to calc RVS: 0x%p\n", (char*)tempaddress+1);
    //wprintf(L"hex test1: %p\n", *((DWORD*)((__int64)tempaddress-3)));
    PVOID CsrPortHandleAddress = ((char*)tempaddress + 1) + *((DWORD*)((__int64)tempaddress - 3));
    wprintf(L"[+] Get CsrPortHandle Address: 0x%p\n", CsrPortHandleAddress);
    CsrPortHandle = *(PVOID*)CsrPortHandleAddress;
    wprintf(L"[+] CsrPortHandle: 0x%08x\n", CsrPortHandle);

    BYTE signaturecode2[] = { 0x48,0x89,0x05, 0x00,0xe8 ,0x00,0x4c,0x8b};
    for (int i = 0; i < SizeOfNtdll; i++)
    {
        tempaddress = (char*)DllBase + i;
        if (!memcmp(signaturecode2, tempaddress, 3)
           && !memcmp((char*)signaturecode2 + 3, (char*)tempaddress + 6, 2)
           && !memcmp((char*)signaturecode2 + 5, (char*)tempaddress + 11, 3))
        {
            //wprintf(L"found: 0x%p\n", tempaddress);
            break;
        }
    }
    if (i == SizeOfNtdll)
    {
        wprintf(L"[-] No Found CsrPortMemoryRemoteDelta\n");
        CsrPortMemoryRemoteDelta = 0;
        return -1;
    }
    tempaddress = (char*)tempaddress + 3;
    //wprintf(L"tempaddress= %p\n", tempaddress);
    //wprintf(L"hex test2 RSVA: %p\n", (PVOID) * ((DWORD*)(tempaddress)));
    PVOID CsrPortMemoryRemoteDeltaAddress = (char*)tempaddress + 4 + *((DWORD*)(tempaddress));
    wprintf(L"[+] Get CsrPortMemoryRemoteDelta Address: 0x%p\n", CsrPortMemoryRemoteDeltaAddress);
    CsrPortMemoryRemoteDelta = *(ULONG_PTR*)CsrPortMemoryRemoteDeltaAddress;
    wprintf(L"[+] CsrPortMemoryRemoteDelta: 0x%p\n", (PVOID)CsrPortMemoryRemoteDelta);

    //我不调试是0x5c 调试就变成 0x50 ?????????????
    //0x00007FFE77919231+00000000000C1A17 in [RW]
    // PVOID CsrPortHandleAddress_RVS = &((char*)tempaddress - 3);

    return 0;
}
void GetBasepConstructSxsCreateProcessMessage(PVOID DllBase, DWORD SizeofKernel32)
{
    //BYTE signaturecode[] = { 0x4c,0x89,0x4c,0x24,0x20,0x48,0x89,0x4c,0x24,0x08,0x53,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41 };
    BYTE signaturecode[] = { 0x08,0x53,0x55,0x56,0x57,0x41,0x54,0x41 };
    //BYTE signaturecode2[] = { 0x4c,0x89,0x48,0x89 };
    BYTE signaturecode2[] = { 0x20,0x48,0x89 };
    //BYTE signaturecode2[] = { 0x41,0x57,0x48,0x81,0xec };
    for (int i = 0; i < SizeofKernel32 - 24 && BasepConstructSxsCreateProcessMessage_2008_Address == 0; i+=1)
    {
        if (!memcmp(signaturecode, (char*)DllBase + i, sizeof(signaturecode)))
        {
            //wprintf(L"Address = 0x%p\n", (char*)DllBase + i);
            for (int j = 0; j < 6; j++)
            {
                if (!memcmp(signaturecode2, (char*)DllBase + i - j, 3))
                {
                    //wprintf(L"Final Address2 = 0x%p\n", (char*)DllBase + i);
                    BasepConstructSxsCreateProcessMessage_2008_Address = (char*)DllBase + i - ((int)((char*)DllBase + i)%16);
                    wprintf(L"[+] Got Unexported BasepConstructSxsCreateProcessMessage: 0x%p\n", BasepConstructSxsCreateProcessMessage_2008_Address);
                    break;
                }
            }
        }
    }
}
BOOL SW3_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (SW3_SyscallList.Count) return TRUE;
    PPEB Peb = (PPEB)__readgsqword(0x60);
    PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectoryNtdll = NULL;
    PVOID DllBase = NULL;
    PVOID Temp = 0;
    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
    DWORD SizeOfNtdll = 0;
    PVOID Kernel32 = 0;
    DWORD SizeofKernel32 = 0;
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

        if ((*(ULONG*)DllName | 0x20202020) == 'nrek' && (*(ULONG*)(DllName + 4) | 0x20202020) == '23le')
        {
            //wprintf(L"OK Kernel32: %p\n", DllBase);
            Kernel32 = DllBase;
            SizeofKernel32 = NtHeaders->OptionalHeader.SizeOfImage;
        }
     
        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c)
        {
            Temp = DllBase;
            SizeOfNtdll = NtHeaders->OptionalHeader.SizeOfImage;
            ExportDirectoryNtdll = ExportDirectory;
        }
    }


    if (!ExportDirectory) return FALSE;
    DllBase = Temp;
    ExportDirectory = ExportDirectoryNtdll;
    OSBuildNumber = Peb->OSBuildNumber;
    GetCsrPortHandle(DllBase, SizeOfNtdll);
    if (OSBuildNumber <= 7601)
    {
        wprintf(L"[*] Finding GetBasepConstructSxsCreateProcessMessage...\n");
        GetBasepConstructSxsCreateProcessMessage(Kernel32, SizeofKernel32);
    }
    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW3_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;
    
    do
    {
        PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = SW3_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address(SW3_RVA2VA(PVOID, DllBase, Entries[i].Address));

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

    return TRUE;
}
EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}
EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return SW3_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}
EXTERN_C PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    DWORD index = ((DWORD) rand()) % SW3_SyscallList.Count;

    while (FunctionHash == SW3_SyscallList.Entries[index].Hash){
        // Spoofing the syscall return address
        index = ((DWORD) rand()) % SW3_SyscallList.Count;
    }
    return SW3_SyscallList.Entries[index].SyscallAddress;
}
