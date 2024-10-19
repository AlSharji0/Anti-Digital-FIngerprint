#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        PDLL_EXTENSION pDllExt = (PDLL_EXTENSION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DLL_EXTENSION)); //Allocate data for tje Dll Extension.
        

        pDllExt->ml_semaphore = CreateSemaphore(NULL, 0, 1, NULL); //Semaphore so funcstions dont race condition/overwrite.



    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


