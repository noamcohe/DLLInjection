#include "pch.h"

#define PATH "C:\\Operating systems\\DLLInjectionExercise\\DLLInjectionExercise\\x64\\Release\\DLLInjectionExercise.dll"
#define BUFFER_SIZE 100
#define PROCESS_ID 10108


int main() {

	// Get full path of DLL to inject:
	CHAR  buffer[BUFFER_SIZE] = "";
	DWORD path = GetFullPathNameA
	(
	PATH,							// lpFileName - The name of file.
	BUFFER_SIZE,					// nBufferLength - The size of the buffer, to receive the null-terminated string
									// for the drive and path, in TCHARs.
	buffer,							// lpBuffer - A pointer to a buffer that receives the null-terminated string for the drive and path.
	NULL							// lpFilePart
	);

	// If the function fails:
	if (path == 0)
	{
		// Then print an indication that the function fails:
		printf_s("GetFullPathName failed: %d\n", GetLastError());
	}
	

	// Get LoadLibrary function address –
	// the address doesn't change at remote process:
	PVOID addrLoadLibrary = (PVOID)GetProcAddress
	(
	GetModuleHandleA("kernel32.dll"),				// hModule - A handle to the DLL module that contains the function or variable.
	"LoadLibraryA"									// lpProcName - The function or variable name.
	);

	// If the function fails:
	if (addrLoadLibrary == NULL)
	{
		// Then print an indication that the function fails:
		printf_s("GetProcAddress failed: %d\n", GetLastError());
	}


	// Open remote process:
	HANDLE process = OpenProcess
	(
	PROCESS_ALL_ACCESS,			// dwDesiredAccess
	0,							// bInheritHandle
	PROCESS_ID					// dwProcessId
	);

	// If the function fails:
	if (process == NULL)
	{
		// Then print an indication that the function fails:
		printf_s("OpenProcess failed: %d\n", GetLastError());
	}


	// Get a pointer to memory location in remote process,
	// big enough to store DLL path:
	PVOID baseAddress = NULL;
	if (process != NULL)
	{
		baseAddress = (PVOID)VirtualAllocEx
		(
			process,								// hProcess
			NULL,									// lpAddress
			BUFFER_SIZE,							// dwSize
			MEM_COMMIT,								// flAllocationType
			PAGE_EXECUTE_READWRITE					// flProtect
		);

		// If the function fails:
		if (baseAddress == NULL)
		{
			// Then print an indication that the function fails:
			printf_s("VirtualAllocEx failed: %d\n", GetLastError());
		}
	}


	// Write DLL name to remote process memory:
	if (baseAddress != NULL && process != NULL)
	{
		DWORD check = WriteProcessMemory
		(
			process,						// hProcess
			baseAddress,					// lpBaseAddress
			(LPCVOID)buffer,				// lpBuffer
			BUFFER_SIZE,					// nSize
			NULL							// *lpNumberOfBytesWritten
		);

		// If the function fails:
		if (check == 0)
		{
			// Then print an indication that the function fails:
			printf_s("WriteProcessMemory failed: %d\n", GetLastError());
		}
	}


	// Open remote thread, while executing LoadLibrary
	// with parameter DLL name, will trigger DLLMain:
	HANDLE hRemote = NULL;
	if (process != NULL && addrLoadLibrary != NULL)
	{
		hRemote = CreateRemoteThread
		(
			process,											// hProcess
			NULL,												// lpThreadAttributes
			0,													// dwStackSize
			(LPTHREAD_START_ROUTINE)addrLoadLibrary,			// lpStartAddress
			baseAddress,										// lpParameter
			0,													// dwCreationFlags
			0													// lpThreadId
		);

		// If the function fails:
		if (hRemote == NULL)
		{
			// Then print an indication that the function fails:
			printf_s("CreateRemoteThread failed: %d\n", GetLastError());
		}
	}

	if (hRemote != NULL)
	{
		WaitForSingleObject(hRemote, INFINITE);
		CloseHandle(hRemote);
	}

	return 0;
}