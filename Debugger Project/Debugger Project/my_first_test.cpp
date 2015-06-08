#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "Debugger.cpp"

DWORD GetProcessId(LPSTR);
void  PrintRegister(debugger);

int main(void)
{
	debugger dbg = debugger();
	LPVOID   printf_address;

//	ShellExecuteA(NULL, "open", "C:\\WINDOWS\\SYSTEM32\\calc.exe", NULL, NULL, SW_SHOW);
	ShellExecuteA(NULL, "open", "A:\\test.exe", NULL, NULL, SW_SHOW);
	Sleep(150);

	std::cout << "[*] test.exe PID : " << GetProcessId("test.exe") << std::endl;
	dbg.attach(GetProcessId("test.exe"));
	Sleep(1500);

//	std::cout << "[*] Calc PID : " << GetProcessId("calc.exe") << std::endl;
//	dbg.attach(GetProcessId("calc.exe"));
	
//	PrintRegister(dbg);

	printf_address = dbg.func_resolve("msvcrt.dll", "printf");

	std::cout << "printf address : 0x" << printf_address << std::endl;

	dbg.bp_set(printf_address);
	
	dbg.run();
	dbg.detach();

	system("pause");

	return 0;
}

void PrintRegister(debugger dbg)
{
	PDWORD		THREAD_LIST;
	PCONTEXT	thread_context;

	THREAD_LIST = dbg.enumerate_threads();

	for (int i = 0; THREAD_LIST[i] != ENT_OF_THREAD_LIST; i++)
	{
		thread_context = dbg.get_thread_context(THREAD_LIST[i], NULL);

		std::cout << "[*] THREAD ID : " << THREAD_LIST[i] << std::endl;
		std::cout << "    [+] RIP : 0x" << std::hex << thread_context->Rip << std::endl;
		std::cout << "    [+] RSP : 0x" << thread_context->Rsp << std::endl;
		std::cout << "    [+] RBP : 0x" << thread_context->Rbp << std::endl;
		std::cout << "    [+] RAX : 0x" << thread_context->Rax << std::endl;
		std::cout << "    [+] RBX : 0x" << thread_context->Rbx << std::endl;
		std::cout << "    [+] RCX : 0x" << thread_context->Rcx << std::endl;
		std::cout << "    [+] RDX : 0x" << thread_context->Rdx << std::dec << std::endl;
	}
}

DWORD GetProcessId(LPSTR name)
{
	PROCESSENTRY32	pe;
	HANDLE			hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD			pid;

	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapShot, &pe);

	while (Process32Next(hSnapShot, &pe))
	{
		if (strcmp(pe.szExeFile, name) == 0)
		{
			pid = pe.th32ProcessID;
		}
	}


	CloseHandle(hSnapShot);
	return pid;
}