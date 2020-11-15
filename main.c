#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#if defined _WIN64
typedef struct _ProcessInfo
{
	BOOL found;            //4bytes
	DWORD ProcessID;       //4bytes
	HANDLE HandleProcess;  //8bytes
	DWORD64 ModuleAddress; //8bytes
}ProcessInfo; //24bytes: matrix(3/8)
#define P64
#elif defined _WIN32
typedef struct _ProcessInfo
{
	BOOL found;
	HANDLE HandleProcess;
	DWORD ProcessID;
	DWORD ModuleAddress;
}ProcessInfo; //16bytes matrix(2/8)
#else
#define other
#endif

#ifndef other
ProcessInfo setProcessInfo (wchar_t *ProcessName, wchar_t *ModuleName) 
{
#ifdef P64
	ProcessInfo pi = { FALSE, 0, NULL, 0 };
#else
	ProcessInfo pi = { FALSE, NULL, 0, 0 };
#endif
	PROCESSENTRY32W ProcessEntry = {sizeof(PROCESSENTRY32W)};
	MODULEENTRY32W ModuleEntry = {sizeof(MODULEENTRY32W)};
	HANDLE HandleSnapProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	HANDLE HandleSnapModules;

	if (HandleSnapProcess == INVALID_HANDLE_VALUE) 
	{
		printf("Invalid handle value (snap process).\n");
		pi.found = FALSE;
		exit(EXIT_FAILURE);
	}

	if (Process32FirstW(HandleSnapProcess, &ProcessEntry)) 
	{
		do 
		{
			if (lstrcmpW(ProcessName, ProcessEntry.szExeFile) == 0)
			{
				pi.found = TRUE;
				pi.ProcessID = ProcessEntry.th32ProcessID;
				pi.HandleProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.ProcessID);
				CloseHandle(HandleSnapProcess);
				break;
			}
			else continue;
		} while (Process32NextW(HandleSnapProcess, &ProcessEntry));
	}

	if (ModuleName != NULL && pi.found) 
	{
		HandleSnapModules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pi.ProcessID);
		if (Module32FirstW(HandleSnapModules, &ModuleEntry)) 
		{
			do
			{
				if (lstrcmpW((wchar_t*)ModuleEntry.szModule, ModuleName) == 0)
				{
					CloseHandle(HandleSnapModules);
					pi.ModuleAddress = ModuleEntry.modBaseAddr;
					break;
				}
				else continue;

			} while (Module32NextW(HandleSnapModules, &ModuleEntry));
		}
	}

	return pi;
}
#endif
int main(int argc, char **argv)
{
//32bit apps + 64bit modules : target platform 64bit
//32bit apps + 32bit modules : target platform 32bit
//64bit apps + 64bit modules : target platform 64bit
#ifdef P64
	ProcessInfo pi = setProcessInfo(L"Calculator.exe",L"KERNEL32.DLL");
	printf("state: %d\nmodule: %llx\npid: %llx\n", pi.found, pi.ModuleAddress, pi.ProcessID);
#else
	ProcessInfo pi = setProcessInfo(L"Calculator.exe", L"KERNEL32.DLL");
	printf("state: %d\nmodule: %x\npid: %x\n", pi.found, pi.ModuleAddress, pi.ProcessID);
#endif
	return 0;
}