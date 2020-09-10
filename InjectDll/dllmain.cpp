// dllmain.cpp : 定义 DLL 应用程序的入口点。
#define  _CRT_SECURE_NO_WARNINGS
#include "resource.h"
#include <Windows.h>
#include <stdio.h>
#include <vector>


struct Player
{
	void SetBase(void *_this)
	{
		pThis = _this;
		pX = (PFLOAT)((DWORD)pThis + 0x20);
		pY = (PFLOAT)((DWORD)pThis + 0x24);
		pIsGhost = (PBOOL)((DWORD)pThis + 0x0613);
		pHp = (int *)((DWORD)pThis + 0x398);
		pMaxHp = (int *)((DWORD)pThis + 0x390);
		pMana = (int *)((DWORD)pThis + 0x924);
		pMaxMana = (int *)((DWORD)pThis + 0x928);
		pAttackCD = (int *)((DWORD)pThis + 0x338);
		pIsGod = (PBOOL)((DWORD)pThis + 0x673);
	}

	void *pThis = 0;
	PFLOAT pX, pY;
	PBOOL pIsGhost;
	int *pHp;
	int *pMana; // 无用
	int *pMaxHp;
	int *pMaxMana; // 无用
	int *pAttackCD; // 没用
	PBOOL pIsGod; // 没用
};

HMODULE g_hModule; // DLL句柄
Player g_LocalPlayer; // 本地玩家类
DWORD g_dwFnGetLocalPlayer = 0; // 函数地址
DWORD g_dwFnPlayerUpdate = 0; // 函数地址
DWORD g_dwPlayerBase = 0; // 本地玩家基址
BOOL g_bUpdate; // 循环获取玩家信息的线程是否继续运行
BOOL g_bSuperMove; // 超级移动

HWND g_MainDialog; // 外挂窗口
HWND g_StaticInfo; // 玩家信息文本控件
HWND g_Edit_X, g_Edit_Y; // 坐标编辑框
HWND g_EditLocalPlayerBase;

float g_fHomeX, g_fHomeY; // 家坐标
BOOL g_bLockY; // 是否锁定高度
float g_fLockY; // 锁定的高度



DWORD __stdcall EjectThread(LPVOID p);
VOID CenterDialog(HWND hDlg);
DWORD GetAddressFromSignature(std::vector<int> signature, DWORD dwStartAddress, DWORD dwEndAddress);
DWORD GetPlayerBase();
BOOL CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI CreateMainDialog(LPVOID p);
DWORD __stdcall UpdateThread(LPVOID p);
void SuperMove(int step);

// 卸载DLL
DWORD __stdcall EjectThread(LPVOID p)
{
	g_bUpdate = FALSE;
	Sleep(10000); // 等待UI线程结束
	FreeLibraryAndExitThread(g_hModule, 0);
}

// 获取特征码地址
DWORD GetAddressFromSignature(std::vector<int> signature, DWORD dwStartAddress = 0, DWORD dwEndAddress = 0)
{
	if (dwStartAddress == 0 || dwEndAddress == 0)
	{
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		dwStartAddress = (DWORD)si.lpMinimumApplicationAddress;
		dwEndAddress = (DWORD)si.lpMaximumApplicationAddress;
	}
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	DWORD dwProtectFlags = PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS;
	for (DWORD i = dwStartAddress; i < dwEndAddress - signature.size(); )
	{
		//printf("扫描: %X\n", i);
		if (VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi)))
		{
			if (mbi.Protect & dwProtectFlags || !(mbi.State & MEM_COMMIT))
			{
				printf("不可读内存区域: %X -> %X\n", (DWORD)mbi.BaseAddress, (DWORD)mbi.BaseAddress + mbi.RegionSize);
				i += mbi.RegionSize;
				continue; // 跳过不可读地址
			}
			printf("可读内存区域: %X -> %X\n", (DWORD)mbi.BaseAddress, (DWORD)mbi.BaseAddress + mbi.RegionSize);
			for (DWORD k = (DWORD)mbi.BaseAddress; k < (DWORD)mbi.BaseAddress + mbi.RegionSize - signature.size(); k++)
			{
				for (DWORD j = 0; j < signature.size(); j++)
				{
					if (signature.at(j) != -1 && signature.at(j) != *(PBYTE)(k + j))
						break;
					if (j + 1 == signature.size())
						return k;
				}
			}
			i = (DWORD)mbi.BaseAddress + mbi.RegionSize;
		}
	}
	return NULL;
}

// 获取玩家基址
DWORD GetPlayerBase()
{
	if (g_dwFnGetLocalPlayer == 0)
	{
		std::vector<int> sig = { 0xA1, -1 ,-1, -1, -1 ,
			0x8B ,0x15, -1 ,-1 ,-1 ,-1 ,
			0x3B ,0x50 ,0x04 ,0x73 ,0x05 ,0x8B ,0x44 ,0x90 ,0x08 ,0xC3 ,
			0xE8 ,-1, -1, -1 ,-1 ,0xCC };

		g_dwFnGetLocalPlayer = GetAddressFromSignature(sig, 0x23000000, 0x24000000);
		
		if (g_dwFnGetLocalPlayer == 0)
		{
			g_dwFnGetLocalPlayer = GetAddressFromSignature(sig, 0x20000000, 0x23000000);
		}
		if (g_dwFnGetLocalPlayer == 0)
		{
			g_dwFnGetLocalPlayer = GetAddressFromSignature(sig, 0x24000000, 0x26000000);
		}
		if (g_dwFnGetLocalPlayer == 0)
		{
			g_dwFnGetLocalPlayer = GetAddressFromSignature(sig, 0x1F000000, 0x20000000);
		}
		if (g_dwFnGetLocalPlayer == 0)
		{
			g_dwFnGetLocalPlayer = GetAddressFromSignature(sig, 0x26000000, 0x4A000000);
		}
		if (g_dwFnGetLocalPlayer == 0)
		{
			g_dwFnGetLocalPlayer = GetAddressFromSignature(sig, 0x4A000000, 0x50000000);
		}
		if (g_dwFnGetLocalPlayer == 0)
		{
			g_dwFnGetLocalPlayer = GetAddressFromSignature(sig);
		}
	}
	DWORD eax = *(PDWORD)(*(PDWORD)(g_dwFnGetLocalPlayer + 1));
	DWORD edx = *(PDWORD)(*(PDWORD)(g_dwFnGetLocalPlayer + 7));
	eax = *(PDWORD)(eax + edx * 4 + 0x8);
	return eax;
}

// 获取Player::Update函数地址
DWORD GetPlayerUpdate()
{	
	if (g_dwFnPlayerUpdate == 0)
	{
		std::vector<int> sig = {
		0x55, 0x8B, 0xEC, 0x57, 0x56, 0x53, 0x81,
		0xEC, 0x98, 0x09, 0x00, 0x00, 0x8B, 0xF1,
		0x8D, 0xBD, 0x6C, 0xF6, 0xFF, 0xFF, 0xB9,
		0x61, 0x02, 0x00, 0x00, 0x33, 0xC0, 0xF3,
		0xAB, 0x8B, 0xCE, 0x89, 0x8D, 0x68, 0xF6,
		0xFF, 0xFF, 0x89, 0x55, 0xDC, 0x8B, 0x8D,
		0x68, 0xF6, 0xFF, 0xFF, 0xE8, -1, -1, -1,
		-1, 0x8B, 0x45, 0xDC };

		g_dwFnPlayerUpdate = GetAddressFromSignature(sig, 0x23000000, 0x24000000);

		if (g_dwFnPlayerUpdate == 0)
		{
			g_dwFnPlayerUpdate = GetAddressFromSignature(sig, 0x20000000, 0x23000000);
		}
		if (g_dwFnPlayerUpdate == 0)
		{
			g_dwFnPlayerUpdate = GetAddressFromSignature(sig, 0x24000000, 0x26000000);
		}
		if (g_dwFnPlayerUpdate == 0)
		{
			g_dwFnPlayerUpdate = GetAddressFromSignature(sig, 0x1F000000, 0x20000000);
		}
		if (g_dwFnPlayerUpdate == 0)
		{
			g_dwFnPlayerUpdate = GetAddressFromSignature(sig, 0x26000000, 0x4A000000);
		}
		if (g_dwFnPlayerUpdate == 0)
		{
			g_dwFnPlayerUpdate = GetAddressFromSignature(sig, 0x4A000000, 0x50000000);
		}
		if (g_dwFnPlayerUpdate == 0)
		{
			g_dwFnPlayerUpdate = GetAddressFromSignature(sig);
		}
	}
	return g_dwFnPlayerUpdate;
}

// 更新玩家信息，捕获热键
DWORD __stdcall UpdateThread(LPVOID p)
{
	char szBuffer[1000];
	while (g_bUpdate)
	{
		Sleep(20);
		// 锁定高度
		if (g_bLockY) *g_LocalPlayer.pY = g_fLockY;
		// 更新玩家基址
		DWORD dwLatestPlayerBase = GetPlayerBase();
		if (dwLatestPlayerBase != g_dwPlayerBase)
		{
			g_dwPlayerBase = dwLatestPlayerBase;
			g_LocalPlayer.SetBase((void *)g_dwPlayerBase);
			char szbuff[100] = { 0 };
			sprintf(szbuff, "%X", g_dwPlayerBase);
			SetWindowTextA(g_EditLocalPlayerBase, szbuff);
		}
		// 超级移动
		if (g_bSuperMove)SuperMove(50);
		// 更新玩家信息
		sprintf(szBuffer, "player::update: %X\n"
			"getlocalplayer: %X\n"
			"坐标 (%.1f, %.1f)\n"
			"血量: %d\t",			
			g_dwFnPlayerUpdate,
			g_dwFnGetLocalPlayer,
			*g_LocalPlayer.pX, *g_LocalPlayer.pY,
			*g_LocalPlayer.pHp);
		SetWindowTextA(g_StaticInfo, szBuffer);
	}
	return 0;
}

// 对话框窗口过程
BOOL CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		// 初始化控件句柄
		g_StaticInfo = GetDlgItem(hDlg, IDC_STATIC_INFO);
		g_Edit_X = GetDlgItem(hDlg, IDC_EDIT_PLAYER_X);
		g_Edit_Y = GetDlgItem(hDlg, IDC_EDIT_PLAYER_Y);
		g_EditLocalPlayerBase = GetDlgItem(hDlg, IDC_EDIT_LOCALPLAYER_BASE);
		
		// 初始化控件内容
		char szbuff[100] = { 0 };
		sprintf(szbuff, "%X", g_dwPlayerBase);
		SetWindowTextA(g_EditLocalPlayerBase, szbuff);

		// 启动后台线程
		g_bUpdate = TRUE;
		CreateThread(0, 0, UpdateThread, 0, 0, 0);
		return TRUE;
	}
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{		
		case IDC_CHECK_GHOST:
		{
			HWND child = GetDlgItem(hDlg, IDC_CHECK_GHOST);
			int ret = SendMessage(child, BM_GETCHECK, 0, 0);
			if (ret == BST_CHECKED)
			{
				*g_LocalPlayer.pIsGhost = TRUE;
			}
			else
			{
				*g_LocalPlayer.pIsGhost = FALSE;
			}
			return TRUE;
		}
		case IDC_CHECK_SUPER_MOVE:
		{
			HWND child = GetDlgItem(hDlg, IDC_CHECK_SUPER_MOVE);
			int ret = SendMessage(child, BM_GETCHECK, 0, 0);
			if (ret == BST_CHECKED)
			{
				g_bSuperMove = TRUE;
			}
			else
			{
				g_bSuperMove = FALSE;
			}
			return TRUE;
		}
		case IDC_CHECK_LOCK_Y:
		{
			HWND child = GetDlgItem(hDlg, IDC_CHECK_LOCK_Y);
			int ret = SendMessage(child, BM_GETCHECK, 0, 0);
			if (ret == BST_CHECKED)
			{
				g_bLockY = TRUE;
				g_fLockY = *g_LocalPlayer.pY;
			}
			else
			{
				g_bLockY = FALSE;
			}
			
			return TRUE;
		}
		case IDC_BUTTON_ADD_HP:
		{
			*g_LocalPlayer.pMaxHp += 100000;
			*g_LocalPlayer.pHp += 100000;
			return TRUE;
		}
		case IDC_BUTTON_SUB_HP:
		{
			*g_LocalPlayer.pMaxHp -= 100000;
			*g_LocalPlayer.pHp -= 100000;
			return TRUE;
		}
		case IDC_BUTTON_TP:
		{
			HWND hX = GetDlgItem(hDlg, IDC_EDIT_PLAYER_X);
			HWND hY = GetDlgItem(hDlg, IDC_EDIT_PLAYER_Y);
			float x, y;
			char szBuffer[100] = { 0 };
			GetWindowText(hX, szBuffer, 100);
			sscanf(szBuffer, "%f", &x);
			memset(szBuffer, 0, 100);
			GetWindowText(hY, szBuffer, 100);
			sscanf(szBuffer, "%f", &y);
			*g_LocalPlayer.pX = x;
			*g_LocalPlayer.pY = y;
		}
		case IDC_BUTTON_SETHOME:
		{
			g_fHomeX = *g_LocalPlayer.pX;
			g_fHomeY = *g_LocalPlayer.pY;
			return TRUE;
		}
		case IDC_BUTTON_GOHOME:
		{
			*g_LocalPlayer.pX = g_fHomeX;
			*g_LocalPlayer.pY = g_fHomeY;
			return TRUE;
		}
		case IDC_BUTTON_DEBUG:
		{
			*g_LocalPlayer.pY -= 10;
			return TRUE;
		}
		}
		return TRUE;
	case WM_CLOSE:
		EndDialog(hDlg, 0);
		CreateThread(0, 0, EjectThread, 0, 0, 0);
		return TRUE;
	}
	return FALSE;
}

DWORD WINAPI CreateMainDialog(LPVOID p)
{
	// 创建控制台
	AllocConsole();
	FILE *fp;
	freopen_s(&fp, "CONOUT$", "w", stdout);
	// AOB扫描内存，得到某些关键函数的地址，从而得到玩家基址等其他信息
	// 获取玩家基址
	g_dwPlayerBase = GetPlayerBase();
	// 获取玩家更新函数基址
	GetPlayerUpdate();
	// 更新玩家全局对象
	g_LocalPlayer.SetBase((void *)g_dwPlayerBase);
	// 关闭控制台
	fclose(fp);
	FreeConsole();
	// 创建外挂界面
	HWND g_MainDialog = CreateDialogA(GetModuleHandleA("InjectDll.dll"), MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);
	ShowWindow(g_MainDialog, SW_SHOW);
	UpdateWindow(g_MainDialog);
	// 消息循环（必须和创建窗口在同一线程）
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		g_hModule = hModule;
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)CreateMainDialog, 0, 0, 0);

		break;
	}
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
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


// 超级移动
void SuperMove(int step)
{
	// 左上
	if (GetAsyncKeyState(0x41) && GetAsyncKeyState(0x57))
	{
		*g_LocalPlayer.pX -= step;
		*g_LocalPlayer.pY -= step;
	}
	// 左下
	else if (GetAsyncKeyState(0x41) && GetAsyncKeyState(0x53))
	{
		*g_LocalPlayer.pX -= step;
		*g_LocalPlayer.pY += step;
	}
	// 右上
	else if (GetAsyncKeyState(0x44) && GetAsyncKeyState(0x57))
	{
		*g_LocalPlayer.pX += step;
		*g_LocalPlayer.pY -= step;
	}
	// 右下
	else if (GetAsyncKeyState(0x44) && GetAsyncKeyState(0x53))
	{
		*g_LocalPlayer.pX += step;
		*g_LocalPlayer.pY += step;
	}
	// 上
	else if (GetAsyncKeyState(0x57))
	{
		*g_LocalPlayer.pY -= step;
	}
	// 下
	else if (GetAsyncKeyState(0x53))
	{
		*g_LocalPlayer.pY += step;
	}
	// 左
	else if (GetAsyncKeyState(0x41))
	{
		*g_LocalPlayer.pX -= step;
	}
	// 右
	else if (GetAsyncKeyState(0x44))
	{
		*g_LocalPlayer.pX += step;
	}
	g_fLockY = *g_LocalPlayer.pY;
}