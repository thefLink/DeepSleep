#pragma once

#include <stdint.h>
#include "windows.h"

#define FAIL 0
#define SUCCESS 1

#define CRYPT_KEY 0x41424344

uint64_t getFunctionPtr(unsigned long, unsigned long);

// ----  KERNEL32 ----
#define CRYPTED_HASH_KERNEL32 0x3102ad31 
#define CRYPTED_HASH_LOADLIBRARYA 0x1efdb3bf
#define CRYTPED_HASH_VIRTUALALLOC 0x796e4cd3
#define CRYPTED_HASH_VIRTUALFREE 0x27cd8c6a
#define CRYPTED_HASH_COPYMEMORY 0x14d8cfcf
#define CRYPTED_HASH_GETSYSTEMINFO 0xc24aacb2
#define CRYPTED_HASH_VIRTUALQUERYEX 0x96d1a8db
#define CRYPTED_HASH_ADDVECTOREDEXCEPTIONHANDLER 0x7693b393
#define CRYPTED_HASH_GETTHREADCONTEXT 0xaae08c86
#define CRYPTED_HASH_SETTHREADCONTEXT 0x3f62d50a
#define CRYPTED_HASH_GETMODULEHANDLEA 0x1b577c1c
#define CRYPTED_HASH_GETCURRENTPROCESS 0x8bcf3663
#define CRYPTED_HASH_VIRTUALPROTECT 0xc50db2c9
#define CRYPTED_HASH_SLEEP 0x4f5ba6ba
#define CRYPTED_HASH_LSTRCMPA 0x93fd9eaf

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
typedef void(WINAPI* SLEEP)();
typedef BOOL(WINAPI* VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
typedef void(WINAPI* COPYMEMORY)(PVOID, void*, SIZE_T);
typedef HANDLE(WINAPI* GETCURRENTPROCESS)(void);
typedef void(WINAPI* GETSYSTEMINFO)(LPSYSTEM_INFO);
typedef SIZE_T(WINAPI* VIRTUALQUERYEX)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef PVOID(WINAPI* ADDVECTOREDEXCEPTIONHANDLER)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef BOOL(WINAPI* GETTHREADCONTEXT)(HANDLE, LPCONTEXT);
typedef BOOL(WINAPI* SETTHREADCONTEXT)(HANDLE, LPCONTEXT);
typedef HMODULE(WINAPI* GETMODULEHANDLE)(LPCSTR);
typedef BOOL(WINAPI* VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef int (WINAPI* LSTRCMPA)(LPCSTR, LPCSTR);

// ---- USER32 ----
#define CRYPTED_HASH_USER32 0x985bec97
#define CRYPTED_HASH_MESSAGEBOXA 0x790d57f0

typedef int(WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

// ---- shlwapi.dll ----
#define CRYPTED_HASH_SHLWAPI 0xe64fd763
#define CRYPTED_HASH_STRSTRA 0x4ef4617c

typedef PCSTR(WINAPI* STRSTRA)(PCSTR, PCSTR);

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;