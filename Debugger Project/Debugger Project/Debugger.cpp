#include <Windows.h>
#include <TlHelp32.h> // structure THREADENTRY32
#include <iostream>
#include <stdio.h>
#include <string.h>

// END OF THREAD LIST. (thread 리스트의 개수를 몰라서 추가했습니다.)
#define   ENT_OF_THREAD_LIST 0x9999999
// breakpoints list의 끝을 표시
#define   END_OF_BREAKPOINTS_LIST "EndOfBreakpointsList"
// Size of thread_list
#define	 THREAD_LIST_SIZE 0x100
// Size of breakpoints List
#define	 BREAKPOINTS_SIZE 0x100

class debugger
{
private:
	int					create_flags;
	STARTUPINFO			startupinfo = STARTUPINFO();
	PROCESS_INFORMATION process_information = PROCESS_INFORMATION();

	HANDLE	h_process;
	DWORD	pid;
	BOOL	debugger_active;

	DEBUG_EVENT debug_event;
	signed int	ctn_status;

	// TlHelp32.h
	THREADENTRY32	thread_entry;
	HANDLE			h_thread;
	DWORD			thread_list[THREAD_LIST_SIZE];
	HANDLE			snapshot;
	BOOL			success;
	CONTEXT			context;

	DWORD exception;
	PVOID exception_address;

	LPVOID read_buf;
	SIZE_T count;
	LPSTR data;
	DWORD length;
	LPSTR c_data;
	LPVOID breakpoints[BREAKPOINTS_SIZE];
	LPVOID original_byte;

	// variables of func_resolve(LPCSTR, LPCSTR);
	HMODULE handle;
	FARPROC address;

	DWORD temp_var = 0;
	LPSTR TMP_THREAD_ID = "";

public:
	// Constructor
	debugger()
	{
		h_process		= NULL;
		pid				= NULL;
		debugger_active = false;
		h_thread		= NULL;
		breakpoints[0]  = END_OF_BREAKPOINTS_LIST;
	}

	LPVOID read_process_memory(LPVOID address, SIZE_T length)
	{
		data     = "";
		read_buf = (LPVOID)malloc(length); // In python: ctypes.create_string_buffer(length); I think this is malloc.
		count    = 0;

		if (!ReadProcessMemory(h_process, address, read_buf, length, &count))
		{
			return NULL;
		}
		else
		{
			strcat(data, (LPSTR)read_buf);
			return data;
		}
	}

	BOOL write_process_memory(LPVOID address, char *data)
	{
		count  = 0;
		length = strlen(data);

		c_data = &data[count];

		if (!WriteProcessMemory(h_process, address, c_data, length, &count))
		{
			std::cout << "[!] error write_process_memory()." << std::endl;
			return false;
		}
		else
		{
			return true;
		}
	}

	BOOL bp_set(LPVOID address)
	{
		BOOL temp = false;
		int i;

		for (i = 0; breakpoints[i] != END_OF_BREAKPOINTS_LIST; i += 2)
		{
			if (breakpoints[i] == address)
			{
				temp = true;
				break;
			}
		}

		if (temp == false)
		{
			try
			{
				original_byte = read_process_memory(address, 1);

				write_process_memory(address, "\xCC");

				breakpoints[i] = address;
				breakpoints[i + 1] = original_byte;
				breakpoints[i + 2] = END_OF_BREAKPOINTS_LIST;
			}
			catch (...)
			{
				std::cout << "[!] Error in bp_set() : " << GetLastError() << std::endl;
				return false;
			}
		}
		
		return true;
	}

	LPVOID func_resolve(LPCSTR DLL, LPCSTR function) // [typedef] (const CHAR *) = LPCSTR = LPCTSTR
	{
		handle = GetModuleHandleA(DLL);
		address = GetProcAddress(handle, function);

		CloseHandle(handle);

		return address;
	}

	void attach(int PID)
	{
		h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

		if (DebugActiveProcess(PID))
		{
			debugger_active = true;
			pid = PID;
			std::cout << "[*] Success DebugActiveProcess()." << std::endl;
		}
		else
		{
			std::cout << "[!] Unable to attach to the process." << std::endl;
			std::cout << "[!] Error Code : " << GetLastError() << std::endl;
		}
	}

	void get_debug_event()
	{
		PCONTEXT ctx;

		debug_event = DEBUG_EVENT();
		ctn_status = DBG_CONTINUE;

		if (WaitForDebugEvent(&debug_event, INFINITE))
		{
			h_thread = open_thread(debug_event.dwThreadId);
			ctx = get_thread_context(h_thread, NULL);

			std::cout << "[E] Event Code : " << debug_event.dwDebugEventCode
					 << " Thread ID : " << debug_event.dwThreadId << std::endl;

			if (debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
			{
				exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
				exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;

				switch (exception)
				{
				case EXCEPTION_ACCESS_VIOLATION:
					std::cout << "[EXCEPTION] ACCESS VIOLATION." << std::endl;
					break;
				case EXCEPTION_BREAKPOINT:
					ctn_status = exception_handler_breakpoint();
					break;
				case EXCEPTION_GUARD_PAGE:
					std::cout << "[EXCEPTION] Guard Page Access Detected." << std::endl;
					break;
				case EXCEPTION_SINGLE_STEP:
					std::cout << "[EXCEPTION] Single Stepping." << std::endl;
					break;
				default:
					break;
				}

				ContinueDebugEvent(debug_event.dwProcessId,
					debug_event.dwThreadId, ctn_status);
			}
		}

		ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, ctn_status);
	}

	DWORD exception_handler_breakpoint()
	{
		std::cout << "[*] Inside the breakpoint handler." << std::endl;
		std::cout << "[*] Exception  Address : 0x" << std::hex << exception_address << std::endl;
	
		return DBG_CONTINUE;
	}

	void run()
	{
		while (debugger_active == true)
		{
			get_debug_event();
		}
	}

	BOOL detach()
	{
		if (DebugActiveProcessStop(pid))
		{
			std::cout << "[*] detach, EXIT." << std::endl;
			return true;
		}
		else
		{
			std::cout << "[!] detach() error" << std::endl;
			return false;
		}
	}

	HANDLE open_thread(int thread_id)
	{
		h_thread = OpenThread(THREAD_ALL_ACCESS, NULL, thread_id);

		if (h_thread != NULL)
		{
			return h_thread;
		}
		else
		{
			std::cout << "[!] open_thread() error." << std::endl;
			return NULL;
		}
	}

	PDWORD enumerate_threads()
	{
		temp_var = 0;

		thread_entry = THREADENTRY32();
		snapshot	 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
		
		if (snapshot != NULL)
		{
			thread_entry.dwSize = sizeof(thread_entry);
			success = Thread32First(snapshot, &thread_entry);

			while (success)
			{
				if (thread_entry.th32OwnerProcessID == pid)
				{
					thread_list[temp_var++] = thread_entry.th32ThreadID;
				}

				success = Thread32Next(snapshot, &thread_entry);
			}

			thread_list[temp_var] = ENT_OF_THREAD_LIST; // end of the thread_list
			CloseHandle(snapshot);
			return thread_list;
		}
		else
		{
			std::cout << "[!] enumerate_threads() error" << std::endl;
			return false;
		}
	}

	PCONTEXT get_thread_context(HANDLE Handle_T, HANDLE h_thread) // get_thread_context 1 :: overloading
	{
		context = CONTEXT();
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

		if (GetThreadContext(Handle_T, &context))
		{
			CloseHandle(Handle_T);
			return &context;
		}
		else
		{
			std::cout << "[!] get_thread_context() error." << std::endl;
			return NULL;
		}
	}

	PCONTEXT get_thread_context(DWORD thread_id, HANDLE h_thread) // get_thread_context 2 :: overloading
	{
		context = CONTEXT();
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

		if (!h_thread)
		{
			open_thread(thread_id);
		}

		h_thread = open_thread(thread_id);
		
		if (GetThreadContext(h_thread, &context))
		{
			CloseHandle(h_thread);
			return &context;
		}
		else
		{
			std::cout << "[!] get_thread_context() error." << std::endl;
			return NULL;
		}
	}

	void load(char *path_to_exe)
	{
		create_flags = DEBUG_PROCESS;

		startupinfo.dwFlags		= 0x01;
		startupinfo.wShowWindow = 0x00;
		// 위 두 옵션은 프로게스가 독립적인 창으로 인식하게 해줌
		startupinfo.cb			= sizeof(startupinfo);
		// cb멤버는 자신의 크기를 가지고 있어야 함. 그러니 초기화 해줌
	
		if (CreateProcessA(path_to_exe, NULL, NULL, NULL, NULL, create_flags, NULL, NULL, (LPSTARTUPINFOA)&startupinfo, &process_information))
		{
			std::cout << "[+] SUCCESS TO LAUNCH." << std::endl;
			std::cout << "[+] PID : " << process_information.dwProcessId << std::endl;

			h_process = OpenProcess(PROCESS_ALL_ACCESS, false, process_information.dwProcessId);
		}
		else
		{
			std::cout << "[!] Error : " << GetLastError() << std::endl;
		}
	}
};