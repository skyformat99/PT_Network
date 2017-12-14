// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

#ifdef _WIN32
#ifdef _WIN64 // _WIN64
#pragma comment(lib,".\\lib\\x64\\libcrypto.lib")
#pragma comment(lib,".\\lib\\x64\\libssl.lib")
#else  //x86
#pragma comment(lib,".\\lib\\x86\\libcrypto.lib")
#pragma comment(lib,".\\lib\\x86\\libssl.lib")

#endif
#endif
#ifdef _DEBUG
#pragma comment(lib,"mbedTLS.lib")
#else
#pragma comment(lib,"mbedTLS_Release.lib")
#endif // _DEBUG


BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD  ul_reason_for_call,
					  LPVOID lpReserved
					 )
{
	switch(ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}

	return TRUE;
}

