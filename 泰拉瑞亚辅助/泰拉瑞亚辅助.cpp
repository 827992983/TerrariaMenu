// 泰拉瑞亚辅助.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>
#include <vector>
#include <tlhelp32.h>
#include "resource.h"



DWORD g_GamePid = 0;

BOOL CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
VOID CenterDialog(HWND hDlg);
BOOL EnableDebugPrivilege();
BOOL Inject();
DWORD GetGamePid();




int main()
{
	EnableDebugPrivilege();
	GetGamePid();
	Inject();
	//printf("初始化...\n");
	//HINSTANCE hInstance = GetModuleHandle(NULL);
	//DialogBoxA(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);
}

// 对话框窗口过程
BOOL CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		printf("对话框创建成功!\n");
		CenterDialog(hDlg);		
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_INJECT:
		{
			Inject();
			return TRUE;
		}
			
		}
		return TRUE;
	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}

VOID CenterDialog(HWND hDlg)
{
	HWND hwndOwner = NULL;
	RECT rcOwner, rcDlg, rc;
	// Get the owner window and dialog box rectangles. 			
	if ((hwndOwner = GetParent(hDlg)) == NULL)
	{
		hwndOwner = GetDesktopWindow();
	}
	GetWindowRect(hwndOwner, &rcOwner);
	GetWindowRect(hDlg, &rcDlg);
	CopyRect(&rc, &rcOwner);

	// Offset the owner and dialog box rectangles so that right and bottom 
	// values represent the width and height, and then offset the owner again 
	// to discard space taken up by the dialog box. 

	OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top);
	OffsetRect(&rc, -rc.left, -rc.top);
	OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom);

	// The new position is the sum of half the remaining space and the owner's 
	// original position. 

	SetWindowPos(hDlg,
		HWND_TOP,
		rcOwner.left + (rc.right / 2),
		rcOwner.top + (rc.bottom / 2),
		0, 0,          // Ignores size arguments. 
		SWP_NOSIZE);
}

// 提权函数：提升为DEBUG权限
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

BOOL Inject()
{	
	DWORD dwPid = g_GamePid;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (INVALID_HANDLE_VALUE == hProcess)
	{
		printf("打开进程失败\n");
		return FALSE;
	}
	char szCurrentPaths[MAX_PATH] = { 0 };
	GetModuleFileName(0, szCurrentPaths, MAX_PATH);
	strcpy(strrchr(szCurrentPaths, '\\') + 1, "InjectDll.dll");
	// 在要注入的进程中申请一块内存，作为LoadLibrary的参数
	//char szDllName[200] = "InjectDll.dll";
	const char *szDllName = szCurrentPaths;
	LPVOID pAddress = VirtualAllocEx(hProcess, NULL, 200, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pAddress, szDllName, strlen(szDllName), NULL);
	// 创建远程线程，线程入口设置为LoadLibrary，这样就可以自动加载dll
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pAddress, 0, NULL);
	printf("创建远程线程成功\n");
	return TRUE;
}

// 获取泰拉瑞亚PID
DWORD GetGamePid()
{
	// 获取进程快照，得到当前所有进程的PID
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("获取进程快照失败\n");
		return -1;
	}
	// 遍历进程
	BOOL bNext = Process32First(hProcessSnapshot, &pe32);
	while (bNext)
	{		
		if (strcmp("Terraria.exe", pe32.szExeFile) == 0)
		{
			g_GamePid = pe32.th32ProcessID;
			printf("Game Pid: %d\n", g_GamePid);
			break;
		}
		bNext = Process32Next(hProcessSnapshot, &pe32);
	}
	return 0;
}