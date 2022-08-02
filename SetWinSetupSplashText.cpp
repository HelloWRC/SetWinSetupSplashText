// SetWinSetupSplashText.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include <WinBase.h>
#include <WinUser.h>



typedef struct REMOTE_DATA {
	LPTHREAD_START_ROUTINE pLoadLibary;
	LPTHREAD_START_ROUTINE pGetProcAddress;
	LPTHREAD_START_ROUTINE pGetModuleHandle;

	LPTHREAD_START_ROUTINE pGetModuleName;
	WCHAR User32DLL[MAX_PATH];
	char nameSetWindowText[128];
	char nameSetBkMode[128];
	char targetText[64];
	HWND hTargetWin;
};


BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID Luid;
	TOKEN_PRIVILEGES tp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))return FALSE;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}


DWORD WINAPI RemoteThreadProc(LPVOID lpParam)
{

	REMOTE_DATA* lpData = (REMOTE_DATA*)lpParam;
	typedef HMODULE(WINAPI* pfnLoadLibrary)(LPCWSTR);
	typedef FARPROC(WINAPI* pfnGetProcAddress)(HMODULE, LPCSTR);
	typedef HMODULE(*pfnGetModuleHandle)(LPCSTR);
	typedef DWORD(WINAPI* pfnGetModuleFileName)(HMODULE, LPSTR, DWORD);

	pfnGetModuleHandle MyGetModuleHandle = (pfnGetModuleHandle)lpData->pGetModuleHandle;
	pfnGetModuleFileName MyGetModuleFileName = (pfnGetModuleFileName)lpData->pGetModuleName;
	pfnGetProcAddress MyGetProcAddress = (pfnGetProcAddress)lpData->pGetProcAddress;
	pfnLoadLibrary MyLoadLibrary = (pfnLoadLibrary)lpData->pLoadLibary;

	typedef int (WINAPI* pfnSetWindowText) (HWND, LPCSTR);
	//加载User32.dll
	HMODULE hUser32Dll = MyLoadLibrary(lpData->User32DLL);
	//加载函数
	pfnSetWindowText MySetWindowText = (pfnSetWindowText)MyGetProcAddress(hUser32Dll, lpData->nameSetWindowText);

	MySetWindowText(lpData->hTargetWin, lpData->targetText);
	return 0;
}


int main(int argc, char **argv)
{
	char targetText[256] = "";
	if (argc <= 1)
		std::cin >> targetText;
	else
		strcpy(targetText, argv[1]);
	// get window handle
	HWND hSplashWindow = FindWindow("FirstUXWndClass", NULL);
	if (!hSplashWindow) {
		std::cout << "Could not found splash window!" << std::endl;
		return 1;
	}
	else {
		//std::cout << "Window found!" << std::endl;
	}

	// get text widget
	HWND hTextWidget = FindWindowEx(hSplashWindow, NULL, "Static", NULL);
	if (!hTextWidget) {
		std::cout << "Could not found text widget!" << std::endl;
		return 1;
	}
	else {
		//std::cout << "Widget found!" << std::endl;
	}
	std::cout << hTextWidget << std::endl;

	// get window PID
	DWORD pid = -1;
	if (!GetWindowThreadProcessId(hSplashWindow, &pid)) {
		std::cout << "Could not get target process id!" << std::endl;
		return 1;
	}
	else {
		//std::cout << "PID:" << pid << std::endl;
	}

	if (!EnableDebugPrivilege()) {
		std::cout << "Could not grant debug privillege!" << std::endl;
		return 1;
	}
	else {
		//std::cout << "Grant debug privillege success!" << std::endl;
	}

	HANDLE remote_proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (remote_proc == NULL) {
		std::cout << "Could not open process!" << std::endl;
		return 1;
	}
	else {
		//std::cout << "Open process success!" << std::endl;
	}

	REMOTE_DATA* pdata = new REMOTE_DATA;
	ZeroMemory(pdata, sizeof(REMOTE_DATA));

	pdata->pGetModuleName = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "GetModuleFileNameA");
	pdata->pGetModuleHandle = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "GetModuleHandleA");
	pdata->pGetProcAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "GetProcAddress");
	pdata->pLoadLibary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");

	strcpy(pdata->targetText, targetText);
	lstrcpyW(pdata->User32DLL, L"User32.dll");
	strcpy(pdata->nameSetWindowText, "SetWindowTextA");
	strcpy(pdata->nameSetBkMode, "SetBkMode");

	pdata->hTargetWin = hTextWidget;

	LPVOID lpRemoteBuf = VirtualAllocEx(remote_proc, NULL, sizeof(REMOTE_DATA), MEM_COMMIT, PAGE_READWRITE); // 存储data结构的数据
	LPVOID lpRemoteProc = VirtualAllocEx(remote_proc, NULL, 0x8000, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // 存储函数的代码
	SIZE_T dwWrittenSize = 0;
	WriteProcessMemory(remote_proc, lpRemoteProc, &RemoteThreadProc, 0x8000, &dwWrittenSize);
	WriteProcessMemory(remote_proc, lpRemoteBuf, pdata, sizeof(REMOTE_DATA), &dwWrittenSize);

	HANDLE hRemoteThread = CreateRemoteThread(remote_proc, NULL, 0, (LPTHREAD_START_ROUTINE)lpRemoteProc, lpRemoteBuf, 0, NULL);
	//std::cout << "Create thread success!" << std::endl;

	WaitForSingleObject(hRemoteThread, INFINITE);
	//std::cout << "Thread ended!" << std::endl;

	VirtualFreeEx(remote_proc, lpRemoteBuf, 0, MEM_RELEASE);
	VirtualFreeEx(remote_proc, lpRemoteProc, 0, MEM_RELEASE);
	CloseHandle(hRemoteThread);
	CloseHandle(remote_proc);

	delete[] pdata;

	// Update window
	//SendMessage(setup_splash, WM_SIZE, 0, NULL);
	//RedrawWindow(setup_splash, NULL, NULL, RDW_ERASENOW);
	HDC hdc = GetDC(hSplashWindow);
	SetBkColor(hdc, 0xFFFFFF);
	SetBkMode(hdc, 1);
	InvalidateRect(hSplashWindow, NULL, true);
	UpdateWindow(hSplashWindow);

	//std::cout << "Window cleared" << std::endl;

	return 0;
}