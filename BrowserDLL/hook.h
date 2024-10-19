#pragma once

// Function bitmask definitions.
#define FUNC_GETSYSTEMINFO            0x01
#define FUNC_NTQUERYSYSTEMINFO        0x02
#define FUNC_GLOBALMEMORYSTATUS       0x04
#define FUNC_GETDEVICECAPS            0x08
#define FUNC_GETSYSTEMMETRICS         0x10
#define FUNC_GETUSERDEFAULTLOCALE     0x20
#define FUNC_GETKEYBOARDLAYOUT        0x40
#define FUNC_GETADAPTERSINFO          0x80
#define FUNC_GETDISKFREESPACE         0x100
#define FUNC_GETBATTERYSTATUS         0x200
#define FUNC_GETTIMEZONEINFO          0x400
#define FUNC_ENUMDISPLAYDEVICES       0x800 



typedef struct _DLL_EXTENSION {
	struct _FUNC_DATA {//Data to be fed to the random forest (Pre-Trained) for decision making.
		int GetSystemInfo, NtQuerySystemInformation, GlobalMemoryStatus, GetDeviceCaps, GetSystemMetrics, GetUserDefaultLocaleName, GetKeyboardLayout, GetAdaptersInfo, GetDiskFreeSpace, GetBatteryStatus, GetTimeZoneInformation, EnumDisplayDevices;
		int combination;
	}FuncData, *pFuncData;

	BOOL fingerprint;
	BOOL processed;
	HANDLE ml_semaphore;
}DLL_EXTENSION, *PDLL_EXTENSION;

extern PDLL_EXTENSION pDllExt;
extern HANDLE semaphore;

