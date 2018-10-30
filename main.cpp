#include <cstdio>
#include <vector>
#include <intrin.h>
#include "drv_image.hpp"
#include "util.hpp"
#include "structs.hpp"
#include <cassert>
#include "Capcom/CapcomWrapper.h"
#include "main.h"

#pragma intrinsic(_disable)  
#pragma intrinsic(_enable)

typedef struct GET_ROUTINE_DATA {
	uintptr_t base;
	const char* name;
	uint16_t ordinal;
	uintptr_t result;
} GetRoutineData;

typedef struct ALLOCATE_POOL_DATA {
	POOL_TYPE type;
	size_t size;
	uintptr_t result;
} AllocatePoolData;

typedef struct COPY_MEMORY_DATA {
	uintptr_t target;
	uintptr_t source;
	size_t size;
} CopyMemoryData;

typedef struct CALL_ENTRY_DATA {
	uintptr_t entryPoint;
	uintptr_t kernelMemory;
	uintptr_t capcomBase;
	NTSTATUS result;
} CallEntryData;

typedef struct ZERO_MEMORY_DATA {
	uintptr_t ptr;
	size_t size;
} ZeroMemoryData;

constexpr auto page_size = 0x1000u;

NON_PAGED_DATA static kernelFuncCall RtlCopyMemory;
NON_PAGED_DATA static kernelFuncCall RtlZeroMemory;
NON_PAGED_DATA static kernelFuncCall RtlFindExportedRoutineByName;
NON_PAGED_DATA static kernelFuncCall ExAllocatePool;
NON_PAGED_DATA static kernelFuncCall DbgPrintEx;

NON_PAGED_CODE void __stdcall GetExportedFunctionByOrdinal(MmGetSystemRoutineAddress_t pMmGetSystemRoutineAddress, PVOID userData) {

	GetRoutineData* grd = (GetRoutineData*)userData;

	const auto dos_header = (PIMAGE_DOS_HEADER)grd->base;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return;
	const auto nt_headers = (PIMAGE_NT_HEADERS64)(grd->base + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return;
	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return;
	const auto export_ptr = (PIMAGE_EXPORT_DIRECTORY)(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + grd->base);
	auto address_of_funcs = (PULONG)(export_ptr->AddressOfFunctions + grd->base);
	for (ULONG i = 0; i < export_ptr->NumberOfFunctions; ++i)
	{
		if (export_ptr->Base + (uint16_t)i == grd->ordinal) {
			grd->result = address_of_funcs[i] + grd->base;
			return;
		}
	}
}


NON_PAGED_CODE void __stdcall GetExportedFunctionByName(MmGetSystemRoutineAddress_t pMmGetSystemRoutineAddress, PVOID userData) {
	GetRoutineData* grd = (GetRoutineData*)userData;
	grd->result = CallWithInterruptsAndSmep(
		RtlFindExportedRoutineByName,
		grd->base, 
		grd->name
	);
}

NON_PAGED_CODE void __stdcall ExAllocatePoolKrnl(MmGetSystemRoutineAddress_t pMmGetSystemRoutineAddress, PVOID userData) {
	AllocatePoolData* apd = (AllocatePoolData*)userData;
	apd->result = CallWithInterruptsAndSmep(
		ExAllocatePool,
		apd->type, 
		apd->size
	);
}

NON_PAGED_CODE void __stdcall RtlCopyMemoryKrnl(MmGetSystemRoutineAddress_t pMmGetSystemRoutineAddress, PVOID userData) {
	CopyMemoryData* cmd = (CopyMemoryData*)userData;
	CallWithInterruptsAndSmep(
		RtlCopyMemory,
		cmd->target, 
		cmd->source,
		cmd->size
	);
}

NON_PAGED_CODE void __stdcall CallEntryPoint(MmGetSystemRoutineAddress_t pMmGetSystemRoutineAddress, PVOID userData) {
	CallEntryData* ced = (CallEntryData*)userData;
	//DbgPrintEx(77, 0, "About to call entry point \n%llx \n%llx \n%llx\n", ced->entryPoint, ced->kernelMemory, ced->capcomBase);
	
	ced->result = CallWithInterruptsAndSmep(
		(PDRIVER_INITIALIZE)ced->entryPoint,
		(_DRIVER_OBJECT*)ced->kernelMemory,
		(PUNICODE_STRING)ced->capcomBase
	);
}

NON_PAGED_CODE void __stdcall RtlZeroMemoryKrnl(MmGetSystemRoutineAddress_t pMmGetSystemRoutineAddress, PVOID userData) {
	ZeroMemoryData* zmd = (ZeroMemoryData*)userData;
	CallWithInterruptsAndSmep(
		RtlZeroMemory,
		zmd->ptr,
		zmd->size
	);
}

void _ZeroMemory(uintptr_t ptr, size_t size) {
	ZeroMemoryData zmd = { 0 };
	zmd.ptr = ptr;
	zmd.size = size;
	RunInKernel(RtlZeroMemoryKrnl, &zmd);
}

NTSTATUS CallEntryPoint(uintptr_t entryPoint, uintptr_t kernelMemory, uintptr_t capcomBase) {
	CallEntryData ced;
	ced.entryPoint = entryPoint;
	ced.kernelMemory = kernelMemory;
	ced.capcomBase = capcomBase;
	RunInKernel(CallEntryPoint, &ced);
	return ced.result;
}

void _RtlCopyMemory(uintptr_t target, uintptr_t source, size_t size) {
	CopyMemoryData cmd;
	cmd.target = target;
	cmd.source = source;
	cmd.size = size;
	RunInKernel(RtlCopyMemoryKrnl, &cmd);
}

uintptr_t GetExportedFunctionByOrdinal(uintptr_t _base, uint16_t _ordinal) {
	GetRoutineData grd = { 0 };
	grd.base = _base;
	grd.ordinal = _ordinal;
	RunInKernel(GetExportedFunctionByOrdinal, &grd);
	return grd.result;
}

uintptr_t GetExportedFunctionByName(uintptr_t _base, const char* _name) {

	GetRoutineData grd = { 0 };
	grd.base = _base;
	grd.name = _name;

	RunInKernel(GetExportedFunctionByName, &grd);

	return grd.result;
}

uintptr_t AllocatePool(size_t size, POOL_TYPE pool_type, const bool page_align, size_t* out_size = nullptr) {
	
	constexpr auto page_size = 0x1000u;

	uintptr_t address = { 0 };

	if (page_align && size % page_size != 0)
	{
		auto pages = size / page_size;
		size = page_size * ++pages;
	}

	AllocatePoolData apd;
	apd.type = pool_type;
	apd.size = size;

	RunInKernel(ExAllocatePoolKrnl, &apd);

	if (out_size != nullptr)
		*out_size = apd.size;

	return apd.result;
	
}

void InitKernelFunction() {
	RtlCopyMemory = GetKernelProcAddress<>("RtlCopyMemory");
	RtlZeroMemory = GetKernelProcAddress<>("RtlZeroMemory");
	RtlFindExportedRoutineByName = GetKernelProcAddress<>("RtlFindExportedRoutineByName");
	ExAllocatePool = GetKernelProcAddress<>("ExAllocatePool");
	DbgPrintEx = GetKernelProcAddress<>("DbgPrintEx");
	//cout << hex << RtlCopyMemory << endl << RtlZeroMemory << endl << RtlFindExportedRoutineByName << endl << ExAllocatePool << endl;
}

int __stdcall main(const int argc, char** argv)
{
	
	if (argc != 2)
	{
		printf("usage: drvmap.exe <driver>\n");
		return 0;
	}

	InitKernelFunction();

	bool capcomload = InitDriver();
	printf("[+] loaded capcom driver\n");
	
	const auto _get_module = [](std::string_view name)
	{
		return GetKernelModule(name);
	};

	const auto _get_export_name = [](uintptr_t base, const char* name)
	{
		return GetExportedFunctionByName(base, name);
	};

	const auto _get_export_ordinal = [](uintptr_t base, uint16_t ord)
	{
		return GetExportedFunctionByOrdinal(base, ord);
	};

	
	sizeof(SYSTEM_INFORMATION_CLASS::SystemBasicInformation);
	std::vector<uint8_t> driver_image;
	drvmap::util::open_binary_file(argv[1], driver_image);
	drvmap::drv_image driver(driver_image);

	const auto kernel_memory = AllocatePool(driver.size(), NonPagedPool, true);

	cout << hex << kernel_memory << endl;
	

	assert(kernel_memory != 0);

	printf("[+] allocated 0x%llX bytes at 0x%I64X\n", driver.size(), kernel_memory);
	
	driver.fix_imports(_get_module, _get_export_name, _get_export_ordinal);

	printf("[+] imports fixed\n");

	driver.map();

	printf("[+] sections mapped in memory\n");

	driver.relocate(kernel_memory);

	printf("[+] relocated\n");
	
	//const auto _RtlCopyMemory = capcom->get_system_routine<drvmap::structs::RtlCopyMemoryFn>(L"RtlCopyMemory");
	
	const auto size = driver.size();
	const auto source = driver.data();
	const auto entry_point = kernel_memory + driver.entry_point();

	_RtlCopyMemory(kernel_memory, (uintptr_t)source, size);
	printf("[+] copied memory\n");

	printf("[+] calling entry point at 0x%I64X\n", entry_point);

	std::string capcomName(globalCapcomDriverName.begin(), globalCapcomDriverName.end());
	auto status = STATUS_SUCCESS;
	const auto capcom_base = GetKernelModule(capcomName);
	printf("capcom base: %llx\n", capcom_base);
	
	status = CallEntryPoint(entry_point, kernel_memory, capcom_base);
	
	if(NT_SUCCESS(status))
	{
		printf("[+] successfully created driver object!\n");

		const auto header_size = driver.header_size();
		
		_ZeroMemory(kernel_memory, header_size);

		printf("[+] wiped headers!\n");
	} 
	else
	{
		printf("[-] creating of driver object failed! 0x%I32X\n", status);

	}

	UnloadCapcomDriver();
	
	printf("[+] unloaded capcom driver: %i\n", capcomload);

	return 0;
}