#include "Global.h"

#include <ntimage.h>

char* Utils::Compare(const char* haystack, const char* needle)
{
    do
    {
        const char* h = haystack;
        const char* n = needle;
        while (tolower(static_cast<unsigned char>(*h)) == tolower(static_cast<unsigned char>(*n)) && *n)
        {
            h++;
            n++;
        }

        if (*n == 0)
            return const_cast<char*>(haystack);
    } while (*haystack++);
    return nullptr;
}

PVOID Utils::GetModuleBase(const char* moduleName)
{
    PVOID address = nullptr;
    ULONG size = 0;

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return nullptr;

#pragma warning(disable : 4996) // 'ExAllocatePool': ExAllocatePool is deprecated, use ExAllocatePool2
    PSYSTEM_MODULE_INFORMATION moduleList = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, size));
    if (!moduleList)
        return nullptr;

    status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, nullptr);
    if (!NT_SUCCESS(status))
        goto end;

    for (ULONG_PTR i = 0; i < moduleList->ulModuleCount; i++)
    {
        ULONG64 pointer = reinterpret_cast<ULONG64>(&moduleList->Modules[i]);
        pointer += sizeof(SYSTEM_MODULE);
        if (pointer > (reinterpret_cast<ULONG64>(moduleList) + size))
            break;

        SYSTEM_MODULE module = moduleList->Modules[i];
        module.ImageName[255] = '\0';
        if (Compare(module.ImageName, moduleName))
        {
            address = module.Base;
            break;
        }
    }

end:
    ExFreePool(moduleList);
    return address;
}

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xA):(IN_RANGE(x,'0','9')?x-'0':0))
#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))
ULONG64 Utils::FindPattern(void* baseAddress, const ULONG64 size, const char* pattern)
{
    BYTE* firstMatch = nullptr;
    const char* currentPattern = pattern;

    BYTE* start = static_cast<BYTE*>(baseAddress);
    const BYTE* end = start + size;

    for (BYTE* current = start; current < end; current++)
    {
        const BYTE byte = currentPattern[0]; if (!byte) return reinterpret_cast<ULONG64>(firstMatch);
        if (byte == '\?' || *static_cast<BYTE*>(current) == GET_BYTE(byte, currentPattern[1]))
        {
            if (!firstMatch) firstMatch = current;
            if (!currentPattern[2]) return reinterpret_cast<ULONG64>(firstMatch);
            ((byte == '\?') ? (currentPattern += 2) : (currentPattern += 3));
        }
        else
        {
            currentPattern = pattern;
            firstMatch = nullptr;
        }
    }

    return 0;
}

ULONG64 Utils::FindPatternImage(void* base, const char* pattern)
{
    ULONG64 match = 0;

    PIMAGE_NT_HEADERS64 headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG64>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
    const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
    for (USHORT i = 0; i < headers->FileHeader.NumberOfSections; ++i)
    {
        const PIMAGE_SECTION_HEADER section = &sections[i];
        if (memcmp(section->Name, ".text", 5) == 0 || *reinterpret_cast<DWORD32*>(section->Name) == 'EGAP')
        {
            match = FindPattern(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(base) + section->VirtualAddress), section->Misc.VirtualSize, pattern);
            if (match)
                break;
        }
    }

    return match;
}

PVOID Utils::GetKernelModuleExport(const PVOID moduleBase, const char* exportName)
{
    if (!moduleBase || !exportName)
        return nullptr;

    const auto* dosHeader = static_cast<const IMAGE_DOS_HEADER*>(moduleBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        reinterpret_cast<ULONG64>(moduleBase) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    const auto& exportDir =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.Size == 0 || exportDir.VirtualAddress == 0)
        return nullptr;

    const auto* exportTable = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        reinterpret_cast<ULONG64>(moduleBase) + exportDir.VirtualAddress);

    if (exportTable->NumberOfNames == 0 ||
        exportTable->AddressOfNames == 0 ||
        exportTable->AddressOfNameOrdinals == 0 ||
        exportTable->AddressOfFunctions == 0)
        return nullptr;

    const auto* addressOfNames = reinterpret_cast<const PULONG>(
        reinterpret_cast<ULONG64>(moduleBase) + exportTable->AddressOfNames);
    const auto* addressOfNameOrdinals = reinterpret_cast<const PWORD>(
        reinterpret_cast<ULONG64>(moduleBase) + exportTable->AddressOfNameOrdinals);
    const auto* addressOfFunctions = reinterpret_cast<const PULONG>(
        reinterpret_cast<ULONG64>(moduleBase) + exportTable->AddressOfFunctions);

    for (ULONG i = 0; i < exportTable->NumberOfNames; i++)
    {
        const char* name = reinterpret_cast<const char*>(
            reinterpret_cast<ULONG64>(moduleBase) + addressOfNames[i]);

        // Use exact (case-insensitive) match, not substring — "ObfReferenceObject"
        // must not match "ObfReferenceObjectWithTag".
        if (_stricmp(name, exportName) == 0)
        {
            const WORD ordinal = addressOfNameOrdinals[i];
            if (ordinal >= exportTable->NumberOfFunctions)
                return nullptr;

            const ULONG functionRva = addressOfFunctions[ordinal];
            if (functionRva == 0)
                return nullptr;

            return reinterpret_cast<PVOID>(
                reinterpret_cast<ULONG64>(moduleBase) + functionRva);
        }
    }

    return nullptr;
}

ULONG32 Utils::FindReferenceCountOffset()
{
    //
    // Discover the OBJECT_HEADER PointerCount field offset by disassembling
    // ObfReferenceObjectWithTag in the loaded ntoskrnl image.  We look for
    // the instruction that touches the PointerCount field — typically:
    //
    //   48 8B 81 <disp32>   mov rax, [rcx + disp32]        (load)
    //   48 8B 89 <disp32>   mov rax, [rcx + disp32]        (alternate)
    //   F0 48 83 41 <d8> 1  lock add qword [rcx + disp8], 1
    //   F0 48 83 49 <d8> 1  lock add qword [rcx + disp8], 1 (neg disp)
    //   F0 48 FF 41 <d8>    lock inc qword [rcx + disp8]
    //   F0 48 FF 49 <d8>    lock inc qword [rcx + disp8]   (neg disp)
    //
    // The displacement is signed: the PointerCount lives *before* the
    // object body (in the OBJECT_HEADER), so we expect a negative
    // displacement and return its absolute value.
    //
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"ObfReferenceObjectWithTag");
    BYTE* routine = static_cast<BYTE*>(MmGetSystemRoutineAddress(&routineName));
    if (!routine)
    {
        //
        // MmGetSystemRoutineAddress could not resolve the function directly.
        // Fall back to exporting it from the ntoskrnl image ourselves.
        //
        PVOID kernelBase = GetModuleBase("ntoskrnl.exe");
        if (!kernelBase)
            return 0;

        routine = static_cast<BYTE*>(GetKernelModuleExport(kernelBase, "ObfReferenceObjectWithTag"));
        if (!routine)
            return 0;
    }

    //
    // Scan the first 128 bytes of ObfReferenceObjectWithTag for an
    // instruction that references the PointerCount field via RCX (the
    // first parameter / object pointer).
    //
    constexpr ULONG scanSize = 128;
    for (ULONG i = 0; i + 7 < scanSize; i++)
    {
        // mov rax, [rcx + disp32]  →  48 8B 81 <disp32>
        if (routine[i] == 0x48 && routine[i + 1] == 0x8B && routine[i + 2] == 0x81)
        {
            const INT32 disp = *reinterpret_cast<INT32*>(&routine[i + 3]);
            if (disp < 0)
                return static_cast<ULONG32>(-disp);
        }

        // mov rax, [rcx + disp32]  →  48 8B 89 <disp32>  (alternate ModRM)
        if (routine[i] == 0x48 && routine[i + 1] == 0x8B && routine[i + 2] == 0x89)
        {
            const INT32 disp = *reinterpret_cast<INT32*>(&routine[i + 3]);
            if (disp < 0)
                return static_cast<ULONG32>(-disp);
        }

        // lock add qword [rcx + disp8], 1  →  F0 48 83 41 <disp8> 01
        //                                    or F0 48 83 49 <disp8> 01 (SIB with disp8, negative)
        if (routine[i] == 0xF0 && routine[i + 1] == 0x48 && routine[i + 2] == 0x83 &&
            (routine[i + 3] == 0x41 || routine[i + 3] == 0x49) &&
            routine[i + 5] == 0x01)
        {
            const INT8 disp = static_cast<INT8>(routine[i + 4]);
            if (disp < 0)
                return static_cast<ULONG32>(-disp);
        }

        // lock inc qword [rcx + disp8]  →  F0 48 FF 41 <disp8>
        //                                   or F0 48 FF 49 <disp8> (neg disp)
        if (routine[i] == 0xF0 && routine[i + 1] == 0x48 && routine[i + 2] == 0xFF &&
            (routine[i + 3] == 0x41 || routine[i + 3] == 0x49))
        {
            const INT8 disp = static_cast<INT8>(routine[i + 4]);
            if (disp < 0)
                return static_cast<ULONG32>(-disp);
        }
    }

    return 0;
}


bool Utils::InitObjectFunctions()
{
    UNICODE_STRING routineName;

    //
    // Resolve ObfReferenceObject / ObfDereferenceObject via the documented
    // MmGetSystemRoutineAddress path (all "Ob" prefix functions are on the
    // system-routine allow-list).  This is the preferred dynamic path.
    //
    RtlInitUnicodeString(&routineName, L"ObfReferenceObject");
    Global::pObfReferenceObject = MmGetSystemRoutineAddress(&routineName);

    RtlInitUnicodeString(&routineName, L"ObfDereferenceObject");
    Global::pObfDereferenceObject = MmGetSystemRoutineAddress(&routineName);

    //
    // If MmGetSystemRoutineAddress could not resolve the Ob* functions,
    // fall back to parsing the ntoskrnl export table ourselves.
    //
    if (!Global::pObfReferenceObject)
    {
        PVOID kernelBase = GetModuleBase("ntoskrnl.exe");
        if (kernelBase)
            Global::pObfReferenceObject = GetKernelModuleExport(kernelBase, "ObfReferenceObject");
    }

    if (!Global::pObfDereferenceObject)
    {
        PVOID kernelBase = GetModuleBase("ntoskrnl.exe");
        if (kernelBase)
            Global::pObfDereferenceObject = GetKernelModuleExport(kernelBase, "ObfDereferenceObject");
    }

    //
    // MmGetPhysicalMemoryRanges is resolved and cached on first use inside
    // Utils::GetTotalSystemMemory(); no need to duplicate the lookup here.
    // If it cannot be resolved, GetTotalSystemMemory returns 0 and
    // BuildNestedPageTables falls back to a single 512 GB slot, which is
    // sufficient for any consumer memory on this machine.

    //
    // If we have both Obf functions, prefer calling them directly.
    // Otherwise, discover the PointerCount offset by disassembling the
    // kernel and use raw interlocked operations.
    //
    if (Global::pObfReferenceObject && Global::pObfDereferenceObject)
    {
        Global::UseObFunctions = true;
    }
    else
    {
        Global::ReferenceCountOffset = FindReferenceCountOffset();
        if (Global::ReferenceCountOffset == 0)
            return false;
        Global::UseObFunctions = false;
    }

    return true;
}

ULONG64 Utils::GetTotalSystemMemory()
{
    //
    // Resolve MmGetPhysicalMemoryRanges once (cached as a static).
    // On Windows 10/11 x64 this is exported from ntoskrnl.exe.
    //
    static PPHYSICAL_MEMORY_RANGE (*pMmGetPhysicalMemoryRanges)(VOID) = nullptr;
    static bool tried = false;

    if (!tried)
    {
        tried = true;
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"MmGetPhysicalMemoryRanges");
        pMmGetPhysicalMemoryRanges = reinterpret_cast<decltype(pMmGetPhysicalMemoryRanges)>(
            MmGetSystemRoutineAddress(&name));
        if (!pMmGetPhysicalMemoryRanges)
        {
            PVOID kernelBase = GetModuleBase("ntoskrnl.exe");
            if (kernelBase)
                pMmGetPhysicalMemoryRanges = reinterpret_cast<decltype(pMmGetPhysicalMemoryRanges)>(
                    GetKernelModuleExport(kernelBase, "MmGetPhysicalMemoryRanges"));
        }
    }

    if (!pMmGetPhysicalMemoryRanges)
        return 0;

    const PPHYSICAL_MEMORY_RANGE ranges = pMmGetPhysicalMemoryRanges();
    if (!ranges)
        return 0;

    ULONG64 total = 0;
    for (ULONG i = 0; ranges[i].NumberOfBytes.QuadPart != 0; i++)
    {
        total += static_cast<ULONG64>(ranges[i].NumberOfBytes.QuadPart);
    }

    return total;
}

PVOID Utils::AllocateContiguousMemory(const SIZE_T size)
{
    PHYSICAL_ADDRESS boundary, lowest, highest;
    boundary.QuadPart = lowest.QuadPart = 0;
    highest.QuadPart = -1;

    const PVOID allocated = MmAllocateContiguousMemorySpecifyCacheNode(size, lowest, highest, boundary, MmNonCached, MM_ANY_NODE_OK);
    if (!allocated)
        KeBugCheck(HAL_MEMORY_ALLOCATION);

    RtlZeroMemory(allocated, size);

    return allocated;
}

NTSTATUS Utils::ExecuteOnEachProcessor(NTSTATUS(*callback)(PVOID), const PVOID context)
{
    const ULONG numOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG i = 0; i < numOfProcessors; i++)
    {
        PROCESSOR_NUMBER processorNumber;
        NTSTATUS status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status))
            return status;

        GROUP_AFFINITY affinity;
        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;

        GROUP_AFFINITY oldAffinity;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        status = callback(context);

        KeRevertToUserGroupAffinityThread(&oldAffinity);

        if (!NT_SUCCESS(status))
            return status;
    }

    return STATUS_SUCCESS;
}

extern "C" IMAGE_DOS_HEADER __ImageBase;
NTSTATUS Utils::GetCurrentDriverInfo(ULONG64* baseAddress, SIZE_T* size)
{
    if (__ImageBase.e_magic != IMAGE_DOS_SIGNATURE)
        return STATUS_INVALID_IMAGE_FORMAT;

    const PIMAGE_NT_HEADERS64 headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG64>(&__ImageBase) + __ImageBase.e_lfanew);
    if (headers->Signature != IMAGE_NT_SIGNATURE)
        return STATUS_INVALID_IMAGE_FORMAT;

    *size = headers->OptionalHeader.SizeOfImage;
    *baseAddress = reinterpret_cast<ULONG64>(&__ImageBase);

    return STATUS_SUCCESS;
}

PVOID Utils::AllocatePageAligned(const SIZE_T size)
{
    if (size < PAGE_SIZE)
        KeBugCheck(HAL_MEMORY_ALLOCATION);

    const PVOID allocated = AllocateContiguousMemory(size);
    if (!allocated)
        KeBugCheck(HAL_MEMORY_ALLOCATION);

    RtlZeroMemory(allocated, size);

    return allocated;
}

PEPROCESS Utils::GetNextProcess(PEPROCESS input)
{
    const PLIST_ENTRY currentListEntry = reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<ULONG64>(input) + Global::Offsets::ActiveProcessLinks);
    PLIST_ENTRY nextListEntry = currentListEntry->Flink;
    return reinterpret_cast<PEPROCESS>(reinterpret_cast<ULONG64>(nextListEntry) - Global::Offsets::ActiveProcessLinks);
}

PEPROCESS Utils::FindProcess(const HANDLE processId)
{
    for (PEPROCESS current = PsInitialSystemProcess; current != nullptr; current = GetNextProcess(current))
    {
        const HANDLE currentId = PsGetProcessId(current);
        if (currentId == processId)
            return current;
    }

    return nullptr;
}

bool Utils::CheckMSR(UINT32 msr)
{
    //
    // Ranges resolved at boot from CPUID Fn8000_000A (InitMsrRanges):
    //   [0x00000000, MsrRange01Max]          - MSR0-1 range, read/write allowed
    //   [0xC0000000, 0xC0000000 + MsrRange2Max] - MSR2 range (EFER etc.)
    // Anything else must not be forwarded to the CPU.
    //
    // On Zen 2 (Ryzen 7 4800H) CPUID Fn8000_000A EAX resolves to
    // 0x00021800000000FF, i.e. MsrRange01Max = 0x1FFF and
    // MsrRange2Max = 0x2FFF - the same effective ranges as the old
    // hardcoded 0x00001FFF / 0xC0002FFF / 0xC0011FFF checks, but derived
    // from the CPU itself.
    if (Global::MsrRange01Max == 0 && Global::MsrRange2Max == 0)
        return false;

    if (msr > 0 && msr <= Global::MsrRange01Max)
        return true;

    if (msr > 0xC0000000 && (msr - 0xC0000000) <= Global::MsrRange2Max)
        return true;

    return false;
}

void Utils::InitMsrRanges()
{
    int registers[4];

    __cpuid(registers, CPUID_SVM_FEATURES);

    //
    // EAX bit layout (AMD64 APM, section 15.26 "MSR Intercepts"):
    //   [51:32] - max offset in the 0x00000000-based range (20-bit, max 0x1FFF)
    //   [63:52] - max offset in the 0xC0000000-based range (12-bit, max 0xFFF)
    //
    const UINT64 eax64 =
        static_cast<UINT64>(static_cast<UINT32>(registers[0])) |
        (static_cast<UINT64>(static_cast<UINT32>(registers[3])) << 32);

    Global::MsrRange01Max = static_cast<UINT32>((eax64 >> 32) & 0x1FFF);
    Global::MsrRange2Max = static_cast<UINT32>((eax64 >> 52) & 0xFFF);

    //
    // The MSR permission map holds 2 bits per MSR. The second range
    // (0xC0000000 base) starts at bit 0x800 * CHAR_BIT (AMD APM-defined
    // MSRPM layout). Size the map to cover exactly what this CPU reports,
    // page-aligned.
    //
    constexpr UINT64 SECOND_MSRPM_OFFSET_BITS = 0x800 * CHAR_BIT;
    const UINT64 totalBits = SECOND_MSRPM_OFFSET_BITS + (static_cast<UINT64>(Global::MsrRange2Max) + 1) * 2;
    UINT64 mapSizeBytes = (totalBits + 7) / 8;
    mapSizeBytes = (mapSizeBytes + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;

    Global::MsrPermissionsMapSize = mapSizeBytes ? mapSizeBytes : 2 * PAGE_SIZE;
}

bool Utils::ValidUsermodeAddress(const ULONG64 address)
{
    if (address < 0x1000)
        return false;

    //
    // The user/kernel boundary is not a constant: 64-bit user space (the
    // case on Win11 24H2) puts it at MmHighestUserAddress, while the old
    // 48-bit layout stops at 0x7FFFFFFEFFFF. Global::HighestUserAddress is
    // read at boot from the running kernel, so this is dynamically correct
    // for this system.
    if (address > Global::HighestUserAddress)
        return false;

    return true;
}

void Utils::ReferenceObject(PVOID object)
{
    if (Global::UseObFunctions && Global::pObfReferenceObject)
    {
        using ObfReferenceObject_t = PVOID (*)(PVOID);
        reinterpret_cast<ObfReferenceObject_t>(Global::pObfReferenceObject)(object);
        return;
    }

    //
    // Fallback: the OBJECT_HEADER PointerCount offset was discovered at
    // boot by FindReferenceCountOffset() (disassembly of
    // ObfReferenceObjectWithTag).  The offset is in bytes, not LONG64
    // units, so we cast accordingly.
    //
    if (Global::ReferenceCountOffset)
    {
        auto* countPtr = reinterpret_cast<volatile LONG64*>(
            reinterpret_cast<ULONG64>(object) - Global::ReferenceCountOffset);
        _InterlockedIncrement64(countPtr);
        return;
    }

    //
    // Should never reach here — InitObjectFunctions() refuses to load
    // if neither path is available.
    //
    KeBugCheck(INVALID_DRIVER_HANDLE);
}

void Utils::DereferenceObject(PVOID object)
{
    if (Global::UseObFunctions && Global::pObfDereferenceObject)
    {
        using ObfDereferenceObject_t = VOID (*)(PVOID);
        reinterpret_cast<ObfDereferenceObject_t>(Global::pObfDereferenceObject)(object);
        return;
    }

    if (Global::ReferenceCountOffset)
    {
        auto* countPtr = reinterpret_cast<volatile LONG64*>(
            reinterpret_cast<ULONG64>(object) - Global::ReferenceCountOffset);
        _InterlockedExchangeAdd64(countPtr, -1);
        return;
    }

    KeBugCheck(INVALID_DRIVER_HANDLE);
}

PVOID Utils::GetPreallocatedPool(SIZE_T size)
{
    if (size > PreallocatedPoolSize)
        KeBugCheck(BAD_EXHANDLE);

    static SIZE_T currentPoolIndex = 0;
    if (currentPoolIndex >= ARRAYSIZE(Global::PreallocatedPools))
        KeBugCheck(BAD_EXHANDLE);

    const PVOID pool = Global::PreallocatedPools[currentPoolIndex];
    currentPoolIndex++;

    RtlZeroMemory(pool, size);

    return pool;
}
