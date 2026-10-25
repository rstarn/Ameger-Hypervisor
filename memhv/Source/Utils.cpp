#include "Global.h"
#include "HVLog.h"

#include <ntimage.h>

namespace
{
    constexpr ULONG DirectoryBaseCacheSetCount = 64;
    constexpr ULONG DirectoryBaseCacheWays = 4;
    constexpr ULONG DirectoryBaseCacheSize = DirectoryBaseCacheSetCount * DirectoryBaseCacheWays;

    struct DIRECTORY_BASE_CACHE_ENTRY
    {
        ULONG64 DirectoryBase;
    };

    KSPIN_LOCK DirectoryBaseCacheLock;
    DIRECTORY_BASE_CACHE_ENTRY DirectoryBaseCache[DirectoryBaseCacheSize] = {};
    ULONG DirectoryBaseCacheNextWay[DirectoryBaseCacheSetCount] = {};
    ULONG64 DirectoryBaseCacheGeneration = 0;
    volatile LONG DirectoryBaseCacheInitialized = 0;

    VOID DirectoryBaseProcessNotify(HANDLE parentId, HANDLE processId, BOOLEAN create)
    {
        UNREFERENCED_PARAMETER(parentId);
        UNREFERENCED_PARAMETER(processId);
        UNREFERENCED_PARAMETER(create);

        KIRQL oldIrql;
        KeAcquireSpinLock(&DirectoryBaseCacheLock, &oldIrql);
        RtlZeroMemory(DirectoryBaseCache, sizeof(DirectoryBaseCache));
        RtlZeroMemory(DirectoryBaseCacheNextWay, sizeof(DirectoryBaseCacheNextWay));
        ++DirectoryBaseCacheGeneration;
        KeReleaseSpinLock(&DirectoryBaseCacheLock, oldIrql);
    }
}

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
    // BuildNestedPageTables no longer sizes the NPT from the installed
    // memory (it covers the whole 48-bit GPA space now), but the helper is
    // kept for diagnostics.

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

/*
 * Physical memory ranges reported by the kernel, cached once so that the
 * physical copy path can tell a real RAM page from an MMIO hole without
 * resolving anything at run time: that path executes inside a #VMEXIT
 * handler at whatever IRQL the guest happened to be running at, where
 * MmGetPhysicalMemoryRanges must not be called.
 *
 * A machine reports a handful of ranges; the fixed cap keeps the lookup a
 * bounded linear scan with no allocation.  A list longer than the cap is
 * truncated, which can only reject an address, never accept a non-RAM one.
 */
namespace
{
    constexpr ULONG MaxPhysicalRanges = 64;

    typedef struct _PHYSICAL_RANGE_CACHE_ENTRY
    {
        ULONG64 Base;
        ULONG64 Length;
    } PHYSICAL_RANGE_CACHE_ENTRY;

    PHYSICAL_RANGE_CACHE_ENTRY PhysicalRangeCache[MaxPhysicalRanges];
    ULONG PhysicalRangeCacheCount = 0;

    //
    // 0 = not initialised, 1 = initialising, 2 = cache usable.  Written once
    // at PASSIVE_LEVEL by InitPhysicalMemoryRanges() and only read afterwards,
    // so the copy path needs no lock.
    //
    volatile LONG PhysicalRangeCacheState = 0;

    typedef PPHYSICAL_MEMORY_RANGE (*PFN_GET_PHYSICAL_MEMORY_RANGES)(VOID);

    /*
     * Resolves MmGetPhysicalMemoryRanges once (cached as a static).  On
     * Windows 10/11 x64 this is exported from ntoskrnl.exe.  Both
     * MmGetSystemRoutineAddress and the ZwQuerySystemInformation based
     * export fallback require PASSIVE_LEVEL.
     */
    PFN_GET_PHYSICAL_MEMORY_RANGES GetPhysicalMemoryRangesRoutine()
    {
        static PFN_GET_PHYSICAL_MEMORY_RANGES routine = nullptr;
        static bool tried = false;

        if (!tried)
        {
            tried = true;
            UNICODE_STRING name;
            RtlInitUnicodeString(&name, L"MmGetPhysicalMemoryRanges");
            routine = reinterpret_cast<PFN_GET_PHYSICAL_MEMORY_RANGES>(
                MmGetSystemRoutineAddress(&name));
            if (!routine)
            {
                PVOID kernelBase = Utils::GetModuleBase("ntoskrnl.exe");
                if (kernelBase)
                    routine = reinterpret_cast<PFN_GET_PHYSICAL_MEMORY_RANGES>(
                        Utils::GetKernelModuleExport(kernelBase, "MmGetPhysicalMemoryRanges"));
            }
        }

        return routine;
    }
}

bool Utils::InitPhysicalMemoryRanges()
{
    if (InterlockedCompareExchange(&PhysicalRangeCacheState, 1, 0) != 0)
        return PhysicalRangeCacheState == 2;

    const PFN_GET_PHYSICAL_MEMORY_RANGES routine = GetPhysicalMemoryRangesRoutine();
    const PPHYSICAL_MEMORY_RANGE ranges = routine ? routine() : nullptr;

    ULONG count = 0;
    if (ranges)
    {
        for (; count < MaxPhysicalRanges && ranges[count].NumberOfBytes.QuadPart != 0; count++)
        {
            PhysicalRangeCache[count].Base = static_cast<ULONG64>(ranges[count].BaseAddress.QuadPart);
            PhysicalRangeCache[count].Length = static_cast<ULONG64>(ranges[count].NumberOfBytes.QuadPart);
        }
    }

    PhysicalRangeCacheCount = count;

    /*
     * Publish the cache only when at least one range was obtained.  An empty
     * cache keeps the state at "not initialised", so IsPhysicalRangeValid()
     * rejects every address instead of trusting a list it never got.
     */
    InterlockedExchange(&PhysicalRangeCacheState, count != 0 ? 2 : 0);

    return count != 0;
}

bool Utils::IsPhysicalRangeValid(const ULONG64 physicalAddress, const SIZE_T size)
{
    /*
     * Fail closed: without a filled cache nothing is known to be RAM, so the
     * access is refused rather than let through.  The cache is deliberately
     * not filled from here - see the range-cache comment above.
     */
    if (PhysicalRangeCacheState != 2)
        return false;

    if (physicalAddress == 0 || size == 0)
        return false;

    const ULONG64 end = physicalAddress + size;
    if (end < physicalAddress)
        return false;

    const ULONG count = PhysicalRangeCacheCount;
    for (ULONG i = 0; i < count; i++)
    {
        const ULONG64 base = PhysicalRangeCache[i].Base;
        const ULONG64 rangeEnd = base + PhysicalRangeCache[i].Length;

        // A wrapping entry cannot contain anything; skip it rather than
        // letting the wrapped end widen the match.
        if (rangeEnd <= base)
            continue;

        if (physicalAddress >= base && end <= rangeEnd)
            return true;
    }

    return false;
}

ULONG64 Utils::GetTotalSystemMemory()
{
    //
    // MmGetPhysicalMemoryRanges is resolved and cached by
    // GetPhysicalMemoryRangesRoutine(); the range list itself is cached by
    // InitPhysicalMemoryRanges() for the physical address validation.
    //
    const PFN_GET_PHYSICAL_MEMORY_RANGES pMmGetPhysicalMemoryRanges = GetPhysicalMemoryRangesRoutine();
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

    //
    // Write-back memory: the APM requires the VMCB and the host state save
    // area to be mapped write-back, and every other caller (NPT tables,
    // host stack, MSR permission map) is normal RAM as well.  Nothing here
    // needs uncached semantics.
    //
    const PVOID allocated = MmAllocateContiguousMemorySpecifyCacheNode(size, lowest, highest, boundary, MmCached, MM_ANY_NODE_OK);
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

        //
        // KeSetSystemGroupAffinityThread() only reprograms the affinity mask;
        // the thread actually moves to that core at the next scheduling
        // decision.  The callback below issues VMRUN on whatever core is
        // executing it, so wait until we are really scheduled on the target.
        // Without this, the same core gets virtualized repeatedly while the
        // rest stay unvirtualized, which triple-faults the moment an
        // NPT-restricted page is touched from an active core.  The delay is
        // what lets the scheduler observe the new mask and migrate us - a tight
        // spin would hold the current core forever.
        //
        BOOLEAN onTarget = FALSE;
        LARGE_INTEGER delay;
        delay.QuadPart = -10000;
        for (ULONG attempt = 0; attempt < 1000; ++attempt)
        {
            PROCESSOR_NUMBER current;
            KeGetCurrentProcessorNumberEx(&current);
            if (current.Group == processorNumber.Group && current.Number == processorNumber.Number)
            {
                onTarget = TRUE;
                break;
            }

            KeDelayExecutionThread(Executive, false, &delay);
        }

        if (!onTarget)
        {
            KeRevertToUserGroupAffinityThread(&oldAffinity);
            return STATUS_UNSUCCESSFUL;
        }

        HV::LogNum("ExecuteOnEachProcessor: VMRUN cpu", i);

        status = callback(context);

        HV::LogNum("ExecuteOnEachProcessor: cpu done", i);

        KeRevertToUserGroupAffinityThread(&oldAffinity);

        if (!NT_SUCCESS(status))
            return status;
    }

    return STATUS_SUCCESS;
}

extern "C" IMAGE_DOS_HEADER __ImageBase;
NTSTATUS Utils::GetCurrentDriverInfo(ULONG64* baseAddress, SIZE_T* size)
{
    //
    // Entry() records the real image range from the DRIVER_OBJECT it was
    // entered with.  Prefer it: under manual mapping the PE header is
    // stripped, so __ImageBase sits one page before the allocation and the
    // checks below would reject an otherwise valid image.
    //
    if (Global::DriverBase != 0 && Global::DriverSize != 0)
    {
        *baseAddress = Global::DriverBase;
        *size = static_cast<SIZE_T>(Global::DriverSize);

        return STATUS_SUCCESS;
    }

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
    //
    // Round the request up to a whole number of pages.  The NPT structures
    // built on top of these buffers are walked by the CPU in 4 KB steps, so
    // a partial last page would leave the tail of the table uninitialised
    // (and the PML4 is only sizeof(PML4E_64) * slotCount bytes).  A zero
    // request still gets one page so the caller always has a valid buffer.
    //
    const SIZE_T roundedSize = ((size ? size : 1) + PAGE_SIZE - 1) & ~(static_cast<SIZE_T>(PAGE_SIZE) - 1);

    const PVOID allocated = AllocateContiguousMemory(roundedSize);
    if (!allocated)
        KeBugCheck(HAL_MEMORY_ALLOCATION);

    RtlZeroMemory(allocated, roundedSize);

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
    //
    // ActiveProcessLinks is circular: a "current != nullptr" loop never
    // terminates when the PID is absent.  Walk until the list comes back to
    // the node we started from.
    //
    PEPROCESS start = PsInitialSystemProcess;
    if (!start)
        return nullptr;

    PEPROCESS current = start;
    do
    {
        if (PsGetProcessId(current) == processId)
            return current;

        current = GetNextProcess(current);
    } while (current && current != start);

    return nullptr;
}

NTSTATUS Utils::InitializeDirectoryBaseCache()
{
    KeInitializeSpinLock(&DirectoryBaseCacheLock);
    RtlZeroMemory(DirectoryBaseCache, sizeof(DirectoryBaseCache));
    RtlZeroMemory(DirectoryBaseCacheNextWay, sizeof(DirectoryBaseCacheNextWay));
    DirectoryBaseCacheGeneration = 0;

    //
    // The notify routine only exists to invalidate cached directory bases when
    // processes come and go; it is not needed to resolve a base (GetDirectoryBase
    // reads the EPROCESS field directly). Registering it is therefore optional,
    // and PsSetCreateProcessNotifyRoutine returns STATUS_ACCESS_DENIED when the
    // machine's 16-slot process-notify table is full (common on heavily
    // instrumented systems) or when called in a disallowed context (IRQL above
    // PASSIVE / APCs disabled, which a manual-mapped DriverEntry can hit).
    //
    // That must not take the whole driver down. Leaving DirectoryBaseCacheInitialized
    // at 0 makes ValidateDirectoryBase fail closed while direct resolution keeps
    // working, so the hypervisor still installs and the hide path still runs.
    //
    const NTSTATUS status = PsSetCreateProcessNotifyRoutine(DirectoryBaseProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
    {
        //
        // Registration refused (16-slot notify table full on heavily
        // instrumented systems, or a disallowed context for a manual-mapped
        // DriverEntry).  Log it: IsValidDirectoryBase now falls back to the
        // authoritative process-list walk, so the copy path stays functional
        // - only slightly slower (no cache).
        //
        HV::LogNum("DirectoryBaseCache: notify registration failed, walk fallback active", static_cast<unsigned long long>(status));
        return STATUS_SUCCESS;
    }

    HV::Log("DirectoryBaseCache: notify registered, cache active");

    InterlockedExchange(&DirectoryBaseCacheInitialized, 1);
    return STATUS_SUCCESS;
}

NTSTATUS Utils::ShutdownDirectoryBaseCache()
{
    if (InterlockedExchange(&DirectoryBaseCacheInitialized, 0) == 0)
        return STATUS_SUCCESS;

    const NTSTATUS status = PsSetCreateProcessNotifyRoutine(DirectoryBaseProcessNotify, TRUE);

    KIRQL oldIrql;
    KeAcquireSpinLock(&DirectoryBaseCacheLock, &oldIrql);
    RtlZeroMemory(DirectoryBaseCache, sizeof(DirectoryBaseCache));
    RtlZeroMemory(DirectoryBaseCacheNextWay, sizeof(DirectoryBaseCacheNextWay));
    ++DirectoryBaseCacheGeneration;
    KeReleaseSpinLock(&DirectoryBaseCacheLock, oldIrql);

    return status;
}

bool Utils::IsValidProcess(const PEPROCESS process)
{
    //
    // Every EPROCESS lives in the non-paged pool in kernel space and is
    // 16-byte aligned.  R8 on the VMMCALL path is fully user-controlled, so
    // reject anything that cannot be a kernel object before touching it.
    //
    constexpr ULONG64 canonicalKernelBase = 0xFFFF800000000000;
    constexpr ULONG maxProcessCount = 0x10000;

    const ULONG64 address = reinterpret_cast<ULONG64>(process);
    if (address < canonicalKernelBase || (address & 0xF) != 0)
        return false;

    if (Global::Offsets::ActiveProcessLinks == 0 || PsInitialSystemProcess == nullptr)
        return false;

    //
    // The only trustworthy way to confirm that the pointer really is an
    // EPROCESS is to find it in the kernel's active process list.  The walk
    // starts from a kernel-owned object and is bounded in case the list is
    // corrupt.
    //
    PEPROCESS current = PsInitialSystemProcess;
    for (ULONG i = 0; i < maxProcessCount; i++)
    {
        if (current == process)
            return true;

        if (reinterpret_cast<ULONG64>(current) < canonicalKernelBase)
            return false;

        current = GetNextProcess(current);
        if (current == PsInitialSystemProcess)
            break;
    }

    return false;
}

bool Utils::IsValidDirectoryBase(const ULONG64 directoryBase)
{
    //
    // A directory base that belongs to no live process is an arbitrary page
    // of RAM the guest filled with PTEs, and walking it turns the copy path
    // into an arbitrary physical read/write.  Only bases the kernel itself
    // published in an EPROCESS are accepted.
    //
    if (directoryBase == 0 || (directoryBase & 0xFFF) != 0)
        return false;

    if (Global::Offsets::ActiveProcessLinks == 0 || Global::Offsets::DirectoryTableBase == 0 ||
        PsInitialSystemProcess == nullptr)
        return false;

    //
    // The cache is only an optimization and is only safe while the
    // process-notify callback is registered (it invalidates entries as
    // processes come and go).  When the registration failed - the 16-slot
    // notify table is full on heavily instrumented systems - the cache stays
    // disabled.  The old code refused every directory base in that case,
    // which silently disabled the whole copy path (the client's "Failed to
    // read header").  The process-list walk below is the authoritative
    // validation, so fall back to it, just without reading or filling the
    // cache.
    //
    const bool cacheUsable = InterlockedCompareExchange(&DirectoryBaseCacheInitialized, 0, 0) != 0;

    if (cacheUsable)
    {
        const ULONG64 pageNumber = directoryBase >> PAGE_SHIFT;
        const ULONG cacheSet = static_cast<ULONG>((pageNumber ^ (pageNumber >> 8) ^ (pageNumber >> 16)) & (DirectoryBaseCacheSetCount - 1));
        const ULONG cacheSetStart = cacheSet * DirectoryBaseCacheWays;

        KIRQL oldIrql;
        KeAcquireSpinLock(&DirectoryBaseCacheLock, &oldIrql);
        for (ULONG way = 0; way < DirectoryBaseCacheWays; way++)
        {
            if (DirectoryBaseCache[cacheSetStart + way].DirectoryBase == directoryBase)
            {
                KeReleaseSpinLock(&DirectoryBaseCacheLock, oldIrql);
                return true;
            }
        }

        KeReleaseSpinLock(&DirectoryBaseCacheLock, oldIrql);
    }

    //
    // Walk only on cache misses. Process notifications invalidate cached
    // bases, so repeated VMMCALLs do not traverse the process list.
    //
    constexpr ULONG maxProcessCount = 0x10000;

    PEPROCESS current = PsInitialSystemProcess;
    for (ULONG i = 0; i < maxProcessCount; i++)
    {
        if (!MmIsAddressValid(current))
            return false;

        if (Memory::GetDirectoryBase(current) == directoryBase)
        {
            if (cacheUsable)
            {
                const ULONG64 pageNumber2 = directoryBase >> PAGE_SHIFT;
                const ULONG cacheSet = static_cast<ULONG>((pageNumber2 ^ (pageNumber2 >> 8) ^ (pageNumber2 >> 16)) & (DirectoryBaseCacheSetCount - 1));
                const ULONG cacheSetStart = cacheSet * DirectoryBaseCacheWays;

                KIRQL oldIrql;
                KeAcquireSpinLock(&DirectoryBaseCacheLock, &oldIrql);

                ULONG cacheWay = DirectoryBaseCacheWays;
                for (ULONG way = 0; way < DirectoryBaseCacheWays; way++)
                {
                    if (DirectoryBaseCache[cacheSetStart + way].DirectoryBase == 0)
                    {
                        cacheWay = way;
                        break;
                    }
                }

                if (cacheWay == DirectoryBaseCacheWays)
                {
                    cacheWay = DirectoryBaseCacheNextWay[cacheSet];
                    DirectoryBaseCacheNextWay[cacheSet] = (cacheWay + 1) % DirectoryBaseCacheWays;
                }

                DirectoryBaseCache[cacheSetStart + cacheWay].DirectoryBase = directoryBase;
                KeReleaseSpinLock(&DirectoryBaseCacheLock, oldIrql);
            }

            return true;
        }

        if (!MmIsAddressValid(reinterpret_cast<PBYTE>(current) + Global::Offsets::ActiveProcessLinks))
            return false;

        current = GetNextProcess(current);
        if (current == PsInitialSystemProcess)
            break;
    }

    return false;
}

bool Utils::CheckMSR(UINT32 msr)
{
    //
    // Only MSRs that this CPU actually implements may be forwarded.  The
    // handler reaches the CPU through __readmsr/__writemsr, and both #GP in
    // *host* mode on an unimplemented MSR - the guest cannot catch that, the
    // host bugchecks.  The MSR index is guest controlled, so a range check is
    // not enough: the architectural MSRPM ranges cover thousands of MSRs that
    // do not exist on this part.
    //
    // VM_CR (SVMDIS) and VM_HSAVE_PA (host state area) ARE whitelisted so an
    // intercept does not #GP, but HandleMSRAccess never forwards them to the
    // CPU: reads return zero (hiding the host state area's physical address
    // and any SVM state) and writes are ignored.  A guest probing these MSRs
    // sees exactly what a machine without a hypervisor would show.
    //
    static const UINT32 whitelist[] =
    {
        0xC0000080, // EFER
        0xC0000081, // STAR
        0xC0000082, // LSTAR
        0xC0000083, // CSTAR
        0xC0000084, // FMASK
        0xC0000100, // FS_BASE
        0xC0000101, // GS_BASE
        0xC0000102, // KernelGsBase
        0xC0000103, // TSC_AUX
        0xC0010114, // VM_CR        (never forwarded - see above)
        0xC0010117, // VM_HSAVE_PA  (never forwarded - see above)
    };

    for (SIZE_T i = 0; i < ARRAYSIZE(whitelist); i++)
    {
        if (msr == whitelist[i])
            return true;
    }

    return false;
}

void Utils::InitMsrRanges()
{
    //
    // The MSR permission map has a fixed, architecture-defined geometry
    // (AMD APM Vol. 2, "MSR Intercepts"): 8 KB, four 2 KB ranges of 8192
    // MSRs each, with two bits per MSR (LSB read, MSB write):
    //
    //   range 0 - 0x00000000-0x00001FFF  -> map offset 0x0000
    //   range 1 - 0xC0000000-0xC0001FFF  -> map offset 0x0800
    //   range 2 - 0xC0010000-0xC0011FFF  -> map offset 0x1000
    //   range 3 - reserved               -> map offset 0x1800
    //
    // CPUID Fn8000_000A does NOT describe these ranges.  A probe on this
    // machine (Ryzen 7 4800H, Zen 2) returns EAX = 0x00000001 (SVM
    // revision 1), EBX = 0x00008000 (32768 ASIDs), ECX = 0 and
    // EDX = 0x0013BCFF (feature bits), which matches the CPUID
    // specification (EAX[7:0] revision, EBX[31:0] ASID count).  The old
    // code decoded non-existent EAX[63:52]/[51:32] fields and produced
    // garbage limits (0xCFF / 0x13 on this machine), which would have made
    // CheckMSR reject the EFER write intercept.
    //
    Global::MsrRange01Max = 0x1FFF; // last MSR of range 0
    Global::MsrRange2Max = 0x1FFF; // last offset of ranges 1 and 2

    //
    // 0x1800 bytes of the map are architecturally used (range 3 is
    // reserved), so the allocation must be two pages - one page stops
    // short of the 0xC0010000 range.
    //
    Global::MsrPermissionsMapSize = 2 * PAGE_SIZE;
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

    //
    // The index must be interlocked: GetOrSplitPageTable() runs from both the
    // VMCALL path and the NPF restore path, so two CPUs can split different
    // large pages at the same instant.  A plain increment would hand both the
    // same pool, and their two tables would zero and overwrite each other
    // while the NPT is live.  The split publishes are already atomic 64-bit
    // exchanges of fully-built, equivalent tables, so racing publishers only
    // ever waste one pool - never corrupt the tree.
    //
    static volatile LONG currentPoolIndex = 0;
    const LONG index = InterlockedIncrement(&currentPoolIndex) - 1;
    if (index < 0 || index >= static_cast<LONG>(ARRAYSIZE(Global::PreallocatedPools)))
        return nullptr;

    const PVOID pool = Global::PreallocatedPools[index];

    RtlZeroMemory(pool, size);

    return pool;
}
