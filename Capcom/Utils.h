#pragma once
#include <winternl.h>
#include <windows.h>
#include <vector>
//#include <intrin.h>


using namespace std;

typedef unsigned long long uint64_t;

//const UINT STATUS_INFO_LENGTH_MISMATCH_   =  0xC0000004;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE section;
	PVOID mappedBase;
	PVOID imageBase;
	ULONG imageSize;
	ULONG flags;
	USHORT loadOrderIndex;
	USHORT initOrderIndex;
	USHORT loadCount;
	USHORT offsetToFileName;
	UCHAR fullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG count;
	SYSTEM_MODULE_ENTRY module[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define SystemModuleInformation 0xBull

using fnFreeCall = uint64_t(__fastcall*)(...);

HMODULE ntLib;
uint64_t ntBase;

BOOL InitKernelModuleInfo() {
	vector<BYTE> buffer(1024 * 1024);

	ULONG reqSize = 0;

	do {
		if (!NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer.data(), buffer.size(), &reqSize)) {
			break;
		}

		buffer.resize(reqSize * 2);
	} while (reqSize > buffer.size());

	SYSTEM_MODULE_INFORMATION* moduleInfo = (SYSTEM_MODULE_INFORMATION*)buffer.data();

	char* kernelFileName = (char*)moduleInfo->module[0].fullPathName + moduleInfo->module[0].offsetToFileName;

	ntBase = (uint64_t)moduleInfo->module[0].imageBase;
	ntLib = LoadLibraryA(kernelFileName);

	if (!ntBase || !ntLib) {
		// printf("Failed to get kernel module information!\n");
		return FALSE;
	}

	// printf("Kernel: %s @ %16llx\n", kernelFileName, ntBase);
	return TRUE;
}

BOOL kernelModuleInitialized = FALSE;

template<typename T = fnFreeCall> T GetKernelProcAddress(const char* proc) {
	if (!kernelModuleInitialized) {
		InitKernelModuleInfo();
		kernelModuleInitialized = TRUE;
	}
	FARPROC locProc = GetProcAddress(ntLib, proc);

	if (!locProc) {
		return (T)(nullptr);
	}

	uint32_t delta = (uintptr_t)(locProc)-(uintptr_t)(ntLib);

	return (T)(ntBase + delta);
}

uintptr_t GetKernelModule(const std::string_view kmodule)
{
	NTSTATUS status = 0x0;
	ULONG bytes = 0;
	std::vector<uint8_t> data;
	unsigned long required = 0;


	while ((status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, data.data(), (ULONG)data.size(), &required)) == STATUS_INFO_LENGTH_MISMATCH) {
		data.resize(required);
	}

	if (!NT_SUCCESS(status))
	{
		return 0;
	}
	const auto modules = reinterpret_cast<PRTL_PROCESS_MODULES>(data.data());
	for (unsigned i = 0; i < modules->NumberOfModules; ++i)
	{
		const auto& driver = modules->Modules[i];
		const auto image_base = reinterpret_cast<uintptr_t>(driver.ImageBase);
		std::string base_name = reinterpret_cast<char*>((uintptr_t)driver.FullPathName + driver.OffsetToFileName);
		const auto offset = base_name.find_last_of(".");

		if (kmodule == base_name)
			return reinterpret_cast<uintptr_t>(driver.ImageBase);

		if (offset != base_name.npos)
			base_name = base_name.erase(offset, base_name.size() - offset);

		if (kmodule == base_name)
			return reinterpret_cast<uintptr_t>(driver.ImageBase);
	}

	return 0;
}