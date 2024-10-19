#include "pch.h"

BOOL DecisionTree() {

}


DWORD ThreadMl() {
	while (TRUE) {
		WaitForSingleObject(pDllExt->ml_semaphore, INFINITE);

		Sleep(100); //To allow all of them to input their data into the struct.

		pDllExt->fingerprint = DecisionTree();
		pDllExt->processed = TRUE;

		pDllExt->FuncData = { 0 };

		memset(&(pDllExt->ml_semaphore), 0, sizeof(pDllExt->ml_semaphore)); //Reset the semaphore as its incremented per call.
	}
	return 0;
}
