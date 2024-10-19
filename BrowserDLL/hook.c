#include "pch.h"

GetSystemInfo_t OriginalGetSystemInfo = NULL;
NtQuerySystemInformation_t OriginalNtQuerySystemInformation = NULL;
GlobalMemoryStatus_t OriginalGlobalMemoryStatus = NULL;
GetDeviceCaps_t OriginalGetDeviceCaps = NULL;
GetSystemMetrics_t OriginalGetSystemMetrics = NULL;
GetUserDefaultLocaleName_t OriginalGetUserDefaultLocaleName = NULL;
GetKeyboardLayout_t OriginalGetKeyboardLayout = NULL;
GetAdaptersInfo_t OriginalGetAdaptersInfo = NULL;
GetDiskFreeSpace_t OriginalGetDiskFreeSpace = NULL;
GetBatteryStatus_t OriginalGetBatteryStatus = NULL;
GetTimeZoneInformation_t OriginalGetTimeZoneInformation = NULL;
EnumDisplayDevices_t OriginalEnumDisplayDevices = NULL;

void GetSystemInfo_Hook(LPSYSTEM_INFO lpSystemInfo) {
	pDllExt->FuncData.GetSystemInfo += 1;
	pDllExt->FuncData.combination |= FUNC_GETSYSTEMINFO;

	ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
	WaitForSingleObject(pDllExt->processed, INFINITE);

	if (pDllExt->fingerprint == TRUE) {
		lpSystemInfo->dwNumberOfProcessors = 2;
		lpSystemInfo->dwProcessorType = PROCESSOR_INTEL_386;
		lpSystemInfo->wProcessorLevel = 3;
		lpSystemInfo->dwPageSize = 1024;

	} else OriginalGetSystemInfo(lpSystemInfo);
}

void NtQuerySystemInformation_Hook(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    pDllExt->FuncData.NtQuerySystemInformation += 1;
    pDllExt->FuncData.combination |= FUNC_NTQUERYSYSTEMINFO;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        SYSTEM_BASIC_INFORMATION* basicInfo = (SYSTEM_BASIC_INFORMATION*)SystemInformation;
        basicInfo->NumberOfProcessors = 2;
    } else OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

void GlobalMemoryStatus_Hook(LPMEMORYSTATUS lpMemoryStatus) {
    pDllExt->FuncData.GlobalMemoryStatus += 1;
    pDllExt->FuncData.combination |= FUNC_GLOBALMEMORYSTATUS;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        lpMemoryStatus->dwTotalPhys = 1024 * 1024 * 1024;
        lpMemoryStatus->dwAvailPhys = 512 * 1024 * 1024;
    } else OriginalGlobalMemoryStatus(lpMemoryStatus);
}

int GetDeviceCaps_Hook(HDC hdc, int index) {
    pDllExt->FuncData.GetDeviceCaps += 1;
    pDllExt->FuncData.combination |= FUNC_GETDEVICECAPS;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        if (index == HORZRES) return 1024;
        if (index == VERTRES) return 768;
        return -1; 
    } else return OriginalGetDeviceCaps(hdc, index);
}

int GetSystemMetrics_Hook(int nIndex) {
    pDllExt->FuncData.GetSystemMetrics += 1;
    pDllExt->FuncData.combination |= FUNC_GETSYSTEMMETRICS;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        if (nIndex == SM_CXSCREEN) return 1024;
        if (nIndex == SM_CYSCREEN) return 768;
        return 0;
    } else return OriginalGetSystemMetrics(nIndex);
}

int GetUserDefaultLocaleName_Hook(LPWSTR lpLocaleName, int cchLocaleName) {
    pDllExt->FuncData.GetUserDefaultLocaleName += 1;
    pDllExt->FuncData.combination |= FUNC_GETUSERDEFAULTLOCALE;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        wcscpy(lpLocaleName, L"en-US");
        return wcslen(lpLocaleName);
    } else return OriginalGetUserDefaultLocaleName(lpLocaleName, cchLocaleName);
}

HKL GetKeyboardLayout_Hook(DWORD idThread) {
    pDllExt->FuncData.GetKeyboardLayout += 1;
    pDllExt->FuncData.combination |= FUNC_GETKEYBOARDLAYOUT;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        return (HKL)0x04090409;
    } else return OriginalGetKeyboardLayout(idThread);
}

DWORD GetAdaptersInfo_Hook(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) {
    pDllExt->FuncData.GetAdaptersInfo += 1;
    pDllExt->FuncData.combination |= FUNC_GETADAPTERSINFO;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        // Fake MAC address
        strcpy(pAdapterInfo->Address, "\x00\x11\x22\x33\x44\x55"); //Not very sure if this is correct.
        return ERROR_SUCCESS;
    } else return OriginalGetAdaptersInfo(pAdapterInfo, pOutBufLen);
}

BOOL GetDiskFreeSpace_Hook(LPCSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector, LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters) {
    pDllExt->FuncData.GetDiskFreeSpace += 1;
    pDllExt->FuncData.combination |= FUNC_GETDISKFREESPACE;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        *lpTotalNumberOfClusters = 1024;
        *lpNumberOfFreeClusters = 512;
        return TRUE;
    } else return OriginalGetDiskFreeSpace(lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters,lpTotalNumberOfClusters);
}

BOOL GetBatteryStatus_Hook(SYSTEM_POWER_STATUS *lpSystemPowerStatus) {
    pDllExt->FuncData.GetBatteryStatus += 1;
    pDllExt->FuncData.combination |= FUNC_GETBATTERYSTATUS;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        lpSystemPowerStatus->BatteryLifePercent = 50;
        lpSystemPowerStatus->BatteryFlag = 0;          //Not very sure about this.
        return TRUE;
    } else return OriginalGetBatteryStatus(lpSystemPowerStatus);
}

DWORD GetTimeZoneInformation_Hook(LPTIME_ZONE_INFORMATION lpTimeZoneInformation) {
    pDllExt->FuncData.GetTimeZoneInformation += 1;
    pDllExt->FuncData.combination |= FUNC_GETTIMEZONEINFO;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        lpTimeZoneInformation->Bias = -300;  //Should be faked to GMT + something.
        wcscpy(lpTimeZoneInformation->StandardName, L"ACEDIA");
        return TIME_ZONE_ID_STANDARD;
    } else return OriginalGetTimeZoneInformation(lpTimeZoneInformation);
}

BOOL EnumDisplayDevices_Hook(LPCWSTR lpDevice, DWORD iDevNum, PDISPLAY_DEVICEW lpDisplayDevice, DWORD dwFlags) {
    pDllExt->FuncData.EnumDisplayDevices += 1;
    pDllExt->FuncData.combination |= FUNC_ENUMDISPLAYDEVICES;

    ReleaseSemaphore(pDllExt->ml_semaphore, 1, NULL);
    WaitForSingleObject(pDllExt->processed, INFINITE);

    if (pDllExt->fingerprint == TRUE) {
        wcscpy(lpDisplayDevice->DeviceName, L"ACEDIA Will Win?");
        return TRUE;
    } else return OriginalEnumDisplayDevices(lpDevice, iDevNum, lpDisplayDevice);
}

//All hooked funcs call ReleaseSemaphore 

VOID InstallIAT() { //Hook the IAT for simplicity. Not enough time for bypassing chrome checks.
    HMODULE hModule = GetModuleHandle(NULL);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR ImportTableEntry = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    while (ImportTableEntry) {
        LPCSTR DllName = (LPCSTR)((BYTE*)hModule + ImportTableEntry->Name); //Each entry in the import table corresponds to a import describtion of a DLL.

        if (strcmp(DllName, "kernel32.dll") == 0) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + ImportTableEntry->FirstThunk);

            while (pThunk->u1.Function) {
                PROC* ppFunc = (PROC*)&pThunk->u1.Function;
                DWORD oldProtect;

                if (*ppFunc == GetProcAddress(GetModuleHandle(DllName), "GetSystemInfo")) {
                    OriginalGetSystemInfo = (GetSystemInfo_t)*ppFunc;
                    VirtualProtect(ppFunc, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    *ppFunc = &GetSystemInfo_Hook;
                    VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
                }
                if(*ppFunc == GetProcAddress(GetModuleHandle(DllName), "GetDiskFreeSpace")){
                    OriginalGetDiskFreeSpace = (GetDiskFreeSpace_t)*ppFunc;
                    VirtualProtect(ppFunc, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    *ppFunc = &GetDiskFreeSpace_Hook;
                    VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
                }
                if (*ppFunc == GetProcAddress(GetModuleHandle(DllName), "GlobalMemoryStatus")) {
                    OriginalGlobalMemoryStatus = (GlobalMemoryStatus_t)*ppFunc;
                    VirtualProtect(ppFunc, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    *ppFunc = &GlobalMemoryStatus_Hook;
                    VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
                }
                if (*ppFunc == GetProcAddress(GetModuleHandle(DllName), "GetTimeZoneInformation")) {
                    OriginalGetTimeZoneInformation = (GetTimeZoneInformation_t)*ppFunc;
                    VirtualProtect(ppFunc, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    *ppFunc = &GetTimeZoneInformation_Hook;
                    VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
                    break;
                }
                pThunk++;
            }
        }
        if (strcmp(DllName, "gdi32.dll") == 0) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + ImportTableEntry->FirstThunk);

            while (pThunk->u1.Function) {
                PROC* ppFunc = (PROC*)&pThunk->u1.Function;
                DWORD oldProtect;

                if (*ppFunc == GetProcAddress(GetModuleHandle(DllName), "GetDeviceCaps ")) {
                    OriginalGetDeviceCaps = (GetDeviceCaps_t)*ppFunc;
                    VirtualProtect(ppFunc, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    *ppFunc = &GetDeviceCaps_Hook;
                    VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
                    break;
                }
                pThunk++;
            }
        }
        if (strcmp(DllName, "user32.dll") == 0) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + ImportTableEntry->FirstThunk);

            while (pThunk->u1.Function) {
                PROC* ppFunc = (PROC*)&pThunk->u1.Function;
                DWORD oldProtect;

                if (*ppFunc == GetProcAddress(GetModuleHandle(DllName), "GetSystemMetrics")) {
                    OriginalGetSystemMetrics = (GetSystemMetrics_t)*ppFunc;
                    VirtualProtect(ppFunc, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    *ppFunc = &GetSystemMetrics_Hook;
                    VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
                }

                if (*ppFunc == GetProcAddress(GetModuleHandle(DllName), "GetUserDefaultLocaleName")) {
                    OriginalGetUserDefaultLocaleName = (GetUserDefaultLocaleName_t)*ppFunc;
                    VirtualProtect(ppFunc, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    *ppFunc = &GetUserDefaultLocaleName_Hook;
                    VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
                }

                if (*ppFunc == GetProcAddress(GetModuleHandle(DllName), "GetKeyboardLayout")) {
                    OriginalGetKeyboardLayout = (GetKeyboardLayout_t)*ppFunc;
                    VirtualProtect(ppFunc, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    *ppFunc = &GetKeyboardLayout_Hook;
                    VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
                }

                if (*ppFunc == GetProcAddress(GetModuleHandle(DllName), "EnumDisplayDevices")) {
                    OriginalEnumDisplayDevices = (EnumDisplayDevices_t)*ppFunc;
                    VirtualProtect(ppFunc, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    *ppFunc = &EnumDisplayDevices_Hook;
                    VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
                    break;
                }
                pThunk++;
            }
        }
        ImportTableEntry++;
    }
}