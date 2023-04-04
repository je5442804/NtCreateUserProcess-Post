//#pragma once
#include "syscalls.hpp"

NTSTATUS CallCsrss(HANDLE hProcess,HANDLE hThread, PS_CREATE_INFO CreateInfo,UNICODE_STRING Win32Path, UNICODE_STRING NtPath,CLIENT_ID ClientId, SECTION_IMAGE_INFORMATION SectionImageInfomation);
#define CSRSRV_SERVERDLL_INDEX          0
#define CSRSRV_FIRST_API_NUMBER         0

#define BASESRV_SERVERDLL_INDEX         1
#define BASESRV_FIRST_API_NUMBER        0

#define CONSRV_SERVERDLL_INDEX          2
#define CONSRV_FIRST_API_NUMBER         512

#define USERSRV_SERVERDLL_INDEX         3
#define USERSRV_FIRST_API_NUMBER        1024

#define ALPC_MSGFLG_REPLY_MESSAGE 0x1
#define ALPC_MSGFLG_LPC_MODE 0x2 // ?
#define ALPC_MSGFLG_RELEASE_MESSAGE 0x10000 // dbg
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000 // dbg
#define ALPC_MSGFLG_WAIT_USER_MODE 0x100000
#define ALPC_MSGFLG_WAIT_ALERTABLE 0x200000
#define ALPC_MSGFLG_WOW64_CALL 0x80000000 // dbg

#define BASE_MSG_SXS_MANIFEST_PRESENT                                   (0x0001)
#define BASE_MSG_SXS_POLICY_PRESENT                                     (0x0002)
#define BASE_MSG_SXS_SYSTEM_DEFAULT_TEXTUAL_ASSEMBLY_IDENTITY_PRESENT   (0x0004)
#define BASE_MSG_SXS_TEXTUAL_ASSEMBLY_IDENTITY_PRESENT                  (0x0008)
#define BASE_MSG_SXS_APP_RUNNING_IN_SAFEMODE                            (0x0010)
#define BASE_MSG_SXS_NO_ISOLATION                                       (0x0020) // rev
#define BASE_MSG_SXS_ALTERNATIVE_MODE                                   (0x0040) // rev
#define BASE_MSG_SXS_DEV_OVERRIDE_PRESENT                               (0x0080) // rev
#define BASE_MSG_SXS_MANIFEST_OVERRIDE_PRESENT                          (0x0100) // rev
#define BASE_MSG_SXS_PACKAGE_IDENTITY_PRESENT                           (0x0400) // rev
#define BASE_MSG_SXS_FULL_TRUST_INTEGRITY_PRESENT                       (0x0800) // rev

#define BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_FEEDBACK_ON                1
#define BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_GUI_WAIT                   2
#define BASE_CREATE_PROCESS_MSG_THREAD_FLAG_CROSS_SESSION               1
#define BASE_CREATE_PROCESS_MSG_THREAD_FLAG_PROTECTED_PROCESS           2

typedef ULONG CSR_API_NUMBER;
#define CSR_MAKE_API_NUMBER( DllIndex, ApiIndex ) \
    (CSR_API_NUMBER)(((DllIndex) << 16) | (ApiIndex))

#define CSR_APINUMBER_TO_SERVERDLLINDEX( ApiNumber ) \
    ((ULONG)((ULONG)(ApiNumber) >> 16))

#define CSR_APINUMBER_TO_APITABLEINDEX( ApiNumber ) \
    ((ULONG)((USHORT)(ApiNumber)))

typedef struct _BASESRV_API_CONNECTINFO {
    IN ULONG ExpectedVersion;
    OUT HANDLE DefaultObjectDirectory;
    OUT ULONG WindowsVersion;
    OUT ULONG CurrentVersion;
    OUT ULONG DebugFlags;
    OUT WCHAR WindowsDirectory[MAX_PATH];
    OUT WCHAR WindowsSystemDirectory[MAX_PATH];
} BASESRV_API_CONNECTINFO, * PBASESRV_API_CONNECTINFO;

#define BASESRV_VERSION 0x10000
//
// Message format for messages sent from the client to the server
typedef enum _BASESRV_API_NUMBER {
    BasepCreateProcess = BASESRV_FIRST_API_NUMBER,             // in: TBaseCreateProcessMsgV1
    BasepDeadEntry1,
    BasepDeadEntry2,
    BasepDeadEntry3,
    BasepDeadEntry4,
    BasepCheckVDM,
    BasepUpdateVDMEntry,
    BasepGetNextVDMCommand,
    BasepExitVDM,
    BasepIsFirstVDM,
    BasepGetVDMExitCode,
    BasepSetReenterCount,
    BasepSetProcessShutdownParam,   // in: TBaseShutdownParamMsg
    BasepGetProcessShutdownParam,   // out: TBaseShutdownParamMsg
    BasepSetVDMCurDirs,
    BasepGetVDMCurDirs,
    BasepBatNotification,
    BasepRegisterWowExec,
    BasepSoundSentryNotification,
    BasepRefreshIniFileMapping,
    BasepDefineDosDevice,          // in: TBaseDefineDosDeviceMsg
    BasepSetTermsrvAppInstallMode,
    BasepSetTermsrvClientTimeZone,
    BasepCreateActivationContext,  // in/out: TBaseSxsCreateActivationContextMsg
    BasepDeadEntry24,
    BasepRegisterThread,
    BasepDeferredCreateProcess,
    BasepNlsGetUserInfo,
    BasepNlsUpdateCacheCount,
    BasepCreateProcess2,           // in: TBaseCreateProcessMsgV2, Win 10 20H1+
    BasepCreateActivationContext2  // in/out: TBaseSxsCreateActivationContextMsgV2, Win 10 20H1+
} BASESRV_API_NUMBER, * PBASESRV_API_NUMBER;

#define PORT_CONNECT 0x0001
#define PORT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1)

typedef struct _CSR_API_CONNECTINFO {
    PVOID SharedSectionBase;
    PVOID SharedStaticServerData;
    PVOID ServerProcessId;
    PVOID Reserved;//8 bytes
    DWORD Reserved2;//4 bytes
    DWORD Reserved3;//4 bytes
    PVOID Reserved4;//8 bytes
} CSR_API_CONNECTINFO, * PCSR_API_CONNECTINFO; //0x30

typedef struct _CSR_CLIENTCONNECT_MSG {
    ULONG ServerDllIndex;
    PVOID ConnectionInformation;
    ULONG ConnectionInformationLength;
} CSR_CLIENTCONNECT_MSG, * PCSR_CLIENTCONNECT_MSG;

typedef struct _CSR_CAPTURE_BUFFER {
    ULONG Length;//0         0x184 = 388
    PVOID RelatedCaptureBuffer;//8            PCSR_CAPTURE_HEADER 0x baadf00d baadf00d = 0xbaadf00dbaadf00d
    ULONG CountMessagePointers; //16
    PCHAR FreeSpace;//24
    ULONG_PTR MessagePointerOffsets[6];//32  // Offsets within CSR_API_MSG of pointers ->previously as pointer at 0x10 [ANYSIZE_ARRAY]
} CSR_CAPTURE_BUFFER, * PCSR_CAPTURE_BUFFER;

typedef struct _CSR_API_MSG {
    PORT_MESSAGE h;
    union {
        CSR_API_CONNECTINFO ConnectionRequest;
        struct {
            PCSR_CAPTURE_BUFFER CaptureBuffer;
            CSR_API_NUMBER ApiNumber;
            ULONG ReturnValue;
            ULONG Reserved;
            union {
                CSR_CLIENTCONNECT_MSG ClientConnect;
                ULONG_PTR ApiMessageData[0x2E];// 6.2+ BASE_CREATEPROCESS_MSG here size = [368]
            } u;
        };
    };
} CSR_API_MSG, * PCSR_API_MSG;

typedef struct _SXS_CONSTANT_WIN32_NT_PATH_PAIR
{
    PCUNICODE_STRING Win32;
    PCUNICODE_STRING Nt;
} SXS_CONSTANT_WIN32_NT_PATH_PAIR;
typedef       SXS_CONSTANT_WIN32_NT_PATH_PAIR* PSXS_CONSTANT_WIN32_NT_PATH_PAIR;
typedef CONST SXS_CONSTANT_WIN32_NT_PATH_PAIR* PCSXS_CONSTANT_WIN32_NT_PATH_PAIR;

typedef struct _SXS_WIN32_NT_PATH_PAIR
{
    PRTL_UNICODE_STRING_BUFFER   Win32;
    PRTL_UNICODE_STRING_BUFFER   Nt;
} SXS_WIN32_NT_PATH_PAIR;
typedef       SXS_WIN32_NT_PATH_PAIR* PSXS_WIN32_NT_PATH_PAIR;
typedef CONST SXS_WIN32_NT_PATH_PAIR* PCSXS_WIN32_NT_PATH_PAIR;

typedef struct _BASE_MSG_SXS_STREAM {
    IN BYTE          FileType;//0
    IN BYTE          PathType;//1
    IN BYTE          HandleType;//2
    IN UNICODE_STRING Path;//8
    IN HANDLE         FileHandle;//24 [24/8=3]
    IN HANDLE         SectionHandle;// 32 SectionHandle

    IN ULONGLONG      Offset; // 40 OK 
    IN SIZE_T         Size; //48 OK
} BASE_MSG_SXS_STREAM, * PBASE_MSG_SXS_STREAM;
typedef const BASE_MSG_SXS_STREAM* PCBASE_MSG_SXS_STREAM;

typedef struct _SXS_OVERRIDE_STREAM {
    UNICODE_STRING Name;
    //Length = 0
    //MaximumLength = 2
    //Buffer = 8
    PVOID          Address;//16
    SIZE_T         Size;//24
} SXS_OVERRIDE_STREAM, * PSXS_OVERRIDE_STREAM;//sizeof = 32
typedef const SXS_OVERRIDE_STREAM* PCSXS_OVERRIDE_STREAM;

typedef struct _BASE_MSG_SXS_HANDLES {
    HANDLE File;
    //
    // Process is the process to map section into, it can
    // be NtCurrentProcess; ensure that case is optimized.
    //
    HANDLE Process;
    HANDLE Section;
    PVOID ViewBase; // Don't use this is in 32bit code on 64bit. This is ImageBaseAddress
} BASE_MSG_SXS_HANDLES, * PBASE_MSG_SXS_HANDLES;

//uncorrected



// Old: 136 = 0x88 New: 456 = 0x1C8 
//========================================================================================================================
typedef struct _BASE_SXS_CREATEPROCESS_MSG_2012 {//win 10 new
    ULONG   Flags; //0
    ULONG   ProcessParameterFlags;//4
    //=====================================================
    HANDLE FileHandle;//8
    UNICODE_STRING Win32ImagePath;//16
    UNICODE_STRING NtImagePath;//32;
    PVOID AppCompatSxsData;//48
    SIZE_T AppCompatSxsDataSize;//56
    BYTE Reserved1[8];//64
    BYTE Reserved2[8];//72 Path???
    PVOID ManifestAddress;//80
    ULONG ManifestSize;//88
    BYTE Reserved3[16];//92->108 error
    USHORT UnknowFlags;//1 + 2 //2012 ONLY && Value = -1
    BYTE Reserved4[8];//112->120
    UNICODE_STRING AssemblyDirectory;//120->136
    UNICODE_STRING CacheSxsLanguageBuffer; //136->152 ===== [17]-[18]
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActCtx_RunLevel;//[19]-[20]/2   152->164 [ (00 00 00 00 | 01 00 00 00)
    ULONG UnknowAppCompat;// [20] + 4 164->168
    ULONG_PTR Reversed;
    //01 00 00 00->ACTCTX_RUN_LEVEL_AS_INVOKER = 1 [应用程序清单请求最低权限级别来运行应用程序]
    UNICODE_STRING AssemblyIdentity;    //176->192 L"-----------------------------------------------------------" [21]-[22] 
    
    //Microsoft.Windows.Shell.notepad
    
} BASE_SXS_CREATEPROCESS_MSG_2012, * PNEW_BASE_SXS_CREATEPROCESS_MSG_2012; //192 Message

//====================================================================================================

typedef struct _BASE_SXS_CREATEPROCESS_MSG_2016 {//win 10 new
    ULONG   Flags; //0
    ULONG   ProcessParameterFlags;//4
    //=====================================================
    HANDLE FileHandle;//8
    UNICODE_STRING Win32ImagePath;//16
    UNICODE_STRING NtImagePath;//32;
    PVOID AppCompatSxsData;//48
    SIZE_T AppCompatSxsDataSize;//56
    BYTE Reserved1[8];//64
    BYTE Reserved2[8];//72 Path???
    PVOID ManifestAddress;//80
    ULONG ManifestSize;//88  +4 
    BYTE Reserved3[16];//92->108 error
    USHORT UnknowFlags;//1 + 2
    BYTE Reserved4[8];//112->120
    UNICODE_STRING AssemblyDirectory;//120->136
    UNICODE_STRING CacheSxsLanguageBuffer; //136->152 ===== [17]-[18]
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActCtx_RunLevel;//[19]-[20]/2   152->164 [ (00 00 00 00 | 01 00 00 00)
    ULONG UnknowAppCompat;// [20] + 4 164->168  //01 00 00 00->ACTCTX_RUN_LEVEL_AS_INVOKER = 1 [应用程序清单请求最低权限级别来运行应用程序]
    UNICODE_STRING AssemblyIdentity;    //168->184 L"-----------------------------------------------------------" [21]-[22] 
    //Microsoft.Windows.Shell.notepad
} BASE_SXS_CREATEPROCESS_MSG_2016, * PNEW_BASE_SXS_CREATEPROCESS_MSG_2016;


typedef struct _BASE_SXS_CREATEPROCESS_MSG {//win 10 new
    ULONG   Flags; //0
    ULONG   ProcessParameterFlags;//4
    //=====================================================
    HANDLE FileHandle;//8
    UNICODE_STRING Win32ImagePath;//16
    UNICODE_STRING NtImagePath;//32;
    PVOID AppCompatSxsData;//48
    SIZE_T AppCompatSxsDataSize;//56
    //========================================
    BYTE Reserved1[8];//64
    BYTE Reserved2[8];//72 Path???
    PVOID ManifestAddress;//80
    ULONG ManifestSize;//88
    BYTE Reserved3[16];//96->112
    BYTE Reserved4[8];//112->120
    UNICODE_STRING AssemblyDirectory;//120->136
    UNICODE_STRING CacheSxsLanguageBuffer; //136->152 ===== [17]-[18] // 
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActCtx_RunLevel;//[19]-[20]/2   152->164 [ (00 00 00 00 | 01 00 00 00) *(_DWORD *)(Message + 156) = 0;
    ULONG UnknowAppCompat;// [20] + 4 164->168
    //01 00 00 00->ACTCTX_RUN_LEVEL_AS_INVOKER = 1 [应用程序清单请求最低权限级别来运行应用程序]
    UNICODE_STRING AssemblyIdentity;    //168->184 L"-----------------------------------------------------------" [21]-[22] //Microsoft.Windows.Shell.notepad
    BYTE Reserved7[8];//184->192 [23] Appcompat_CompatCache Related
    PVOID Unknow_PackageActivationSxsInfo;//192-> [24] USHORT?
    BYTE Reserved[256];//208 [25]
} BASE_SXS_CREATEPROCESS_MSG, * PBASE_SXS_CREATEPROCESS_MSG;


typedef struct _BASE_CREATE_PROCESS {
    HANDLE ProcessHandle;//0
    HANDLE ThreadHandle;//8
    CLIENT_ID ClientId;//16
    ULONG CreationFlags;//32
    ULONG VdmBinaryType;//36
    ULONG VdmTask;//40
    HANDLE hVDM;//48
    union {
        struct
        {
            BASE_SXS_CREATEPROCESS_MSG Sxs;
            ULONGLONG PebAddressNative;
            ULONGLONG PebAddressWow64;//
            USHORT ProcessorArchitecture;
        }win2022;
        struct
        {
            BASE_SXS_CREATEPROCESS_MSG_2016 Sxs;
            ULONGLONG PebAddressNative;
            ULONGLONG PebAddressWow64;//
            USHORT ProcessorArchitecture;
        }win2016;
        struct
        {
            BASE_SXS_CREATEPROCESS_MSG_2012 Sxs;
            ULONGLONG PebAddressNative;
            ULONGLONG PebAddressWow64;//
            USHORT ProcessorArchitecture;
        }win2012;
    }u;
    
} BASE_CREATEPROCESS_MSG, * PBASE_CREATEPROCESS_MSG; //536
//64+56=120
typedef struct _BASE_API_MSG
{
    PORT_MESSAGE          PortMessage;//0
    PCSR_CAPTURE_BUFFER   CaptureBuffer;//40
    CSR_API_NUMBER        ApiNumber;//48
    ULONG                 Status;//52
    ULONG                 Reserved;//56
    union
    {
        BASE_CREATEPROCESS_MSG BaseCreateProcess;//+8 64
    }u;
}BASE_API_MSG, * PBASE_API_MSG;




