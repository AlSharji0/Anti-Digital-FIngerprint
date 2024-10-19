#pragma once
typedef void (WINAPI* GetSystemInfo_t)(LPSYSTEM_INFO);
typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef void (WINAPI* GlobalMemoryStatus_t)(LPMEMORYSTATUS lpBuffer);
typedef int (WINAPI* GetDeviceCaps_t)(HDC hdc, int nIndex);
typedef int (WINAPI* GetSystemMetrics_t)(int nIndex);
typedef int (WINAPI* GetUserDefaultLocaleName_t)(LPWSTR lpLocaleName, int cchLocaleName);
typedef HKL(WINAPI* GetKeyboardLayout_t)(DWORD idThread);
typedef DWORD(WINAPI* GetAdaptersInfo_t)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);
typedef BOOL(WINAPI* GetDiskFreeSpace_t)(LPCSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector, LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters);
typedef BOOL(WINAPI* GetBatteryStatus_t)(SYSTEM_POWER_STATUS* lpSystemPowerStatus);
typedef DWORD(WINAPI* GetTimeZoneInformation_t)(LPTIME_ZONE_INFORMATION lpTimeZoneInformation);
typedef BOOL(WINAPI* EnumDisplayDevices_t)(LPCWSTR lpDevice, DWORD iDevNum, PDISPLAY_DEVICEW lpDisplayDevice, DWORD dwFlags);