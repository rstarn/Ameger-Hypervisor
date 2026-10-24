#pragma once

namespace Utils
{
    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemInformationClassMin = 0,
        SystemBasicInformation = 0,
        SystemProcessorInformation = 1,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemPathInformation = 4,
        SystemNotImplemented1 = 4,
        SystemProcessInformation = 5,
        SystemProcessesAndThreadsInformation = 5,
        SystemCallCountInfoInformation = 6,
        SystemCallCounts = 6,
        SystemDeviceInformation = 7,
        SystemConfigurationInformation = 7,
        SystemProcessorPerformanceInformation = 8,
        SystemProcessorTimes = 8,
        SystemFlagsInformation = 9,
        SystemGlobalFlag = 9,
        SystemCallTimeInformation = 10,
        SystemNotImplemented2 = 10,
        SystemModuleInformation = 11,
        SystemLocksInformation = 12,
        SystemLockInformation = 12,
        SystemStackTraceInformation = 13,
        SystemNotImplemented3 = 13,
        SystemPagedPoolInformation = 14,
        SystemNotImplemented4 = 14,
        SystemNonPagedPoolInformation = 15,
        SystemNotImplemented5 = 15,
        SystemHandleInformation = 16,
        SystemObjectInformation = 17,
        SystemPageFileInformation = 18,
        SystemPagefileInformation = 18,
        SystemVdmInstemulInformation = 19,
        SystemInstructionEmulationCounts = 19,
        SystemVdmBopInformation = 20,
        SystemInvalidInfoClass1 = 20,
        SystemFileCacheInformation = 21,
        SystemCacheInformation = 21,
        SystemPoolTagInformation = 22,
        SystemInterruptInformation = 23,
        SystemProcessorStatistics = 23,
        SystemDpcBehaviourInformation = 24,
        SystemDpcInformation = 24,
        SystemFullMemoryInformation = 25,
        SystemNotImplemented6 = 25,
        SystemLoadImage = 26,
        SystemUnloadImage = 27,
        SystemTimeAdjustmentInformation = 28,
        SystemTimeAdjustment = 28,
        SystemSummaryMemoryInformation = 29,
        SystemNotImplemented7 = 29,
        SystemNextEventIdInformation = 30,
        SystemNotImplemented8 = 30,
        SystemEventIdsInformation = 31,
        SystemNotImplemented9 = 31,
        SystemCrashDumpInformation = 32,
        SystemExceptionInformation = 33,
        SystemCrashDumpStateInformation = 34,
        SystemKernelDebuggerInformation = 35,
        SystemContextSwitchInformation = 36,
        SystemRegistryQuotaInformation = 37,
        SystemLoadAndCallImage = 38,
        SystemPrioritySeparation = 39,
        SystemPlugPlayBusInformation = 40,
        SystemNotImplemented10 = 40,
        SystemDockInformation = 41,
        SystemNotImplemented11 = 41,
        SystemInvalidInfoClass2 = 42,
        SystemProcessorSpeedInformation = 43,
        SystemInvalidInfoClass3 = 43,
        SystemCurrentTimeZoneInformation = 44,
        SystemTimeZoneInformation = 44,
        SystemLookasideInformation = 45,
        SystemSetTimeSlipEvent = 46,
        SystemCreateSession = 47,
        SystemDeleteSession = 48,
        SystemInvalidInfoClass4 = 49,
        SystemRangeStartInformation = 50,
        SystemVerifierInformation = 51,
        SystemAddVerifier = 52,
        SystemSessionProcessesInformation = 53,
        SystemInformationClassMax
    } SYSTEM_INFORMATION_CLASS;

    typedef struct _SYSTEM_MODULE
    {
        ULONG_PTR Reserved[2];
        PVOID Base;
        ULONG Size;
        ULONG Flags;
        USHORT Index;
        USHORT Unknown;
        USHORT LoadCount;
        USHORT ModuleNameOffset;
        CHAR ImageName[256];
    } SYSTEM_MODULE, * PSYSTEM_MODULE;

    typedef struct _SYSTEM_MODULE_INFORMATION
    {
        ULONG_PTR ulModuleCount;
        SYSTEM_MODULE Modules[1];
    } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

    typedef struct _IOC_REQUEST
    {
        PVOID Buffer;
        ULONG Size;
        PVOID OriginalContext;
        PIO_COMPLETION_ROUTINE Original;
    } IOC_REQUEST, * PIOC_REQUEST;

    EXTERN_C
    {
        NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
        NTSTATUS ObReferenceObjectByName(PUNICODE_STRING objectName, ULONG attributes, PACCESS_STATE accessState, ACCESS_MASK desiredAccess, POBJECT_TYPE objectType, KPROCESSOR_MODE accessMode, PVOID parseContext, PVOID* object);
        EXTERN_C ULONG64 MmHighestUserAddress;
    }

    EXTERN_C POBJECT_TYPE* IoDriverObjectType;
    EXTERN_C POBJECT_TYPE* IoDeviceObjectType;

    char* Compare(const char* haystack, const char* needle);
    PVOID GetModuleBase(const char* moduleName);
    ULONG64 FindPattern(void* baseAddress, ULONG64 size, const char* pattern);
    ULONG64 FindPatternImage(void* base, const char* pattern);
    PVOID AllocateContiguousMemory(SIZE_T size);
    NTSTATUS ExecuteOnEachProcessor(NTSTATUS(*callback)(PVOID), PVOID context);
    NTSTATUS GetCurrentDriverInfo(ULONG64* baseAddress, SIZE_T* size);
    PVOID AllocatePageAligned(SIZE_T size);
    PEPROCESS GetNextProcess(PEPROCESS input);
    PEPROCESS FindProcess(HANDLE processId);
    bool CheckMSR(UINT32 msr);
    bool ValidUsermodeAddress(ULONG64 address);

    //
    // Resolves the EPROCESS layout offsets (ActiveProcessLinks,
    // UniqueProcessId, DirectoryTableBase) from the running kernel image.
    // Returns false if the pattern is not found (offsets stay at defaults).
    bool GetOffsets();

    //
    // Dynamically resolves ObfReferenceObject, ObfDereferenceObject, and
    // MmGetPhysicalMemoryRanges from the running kernel via
    // MmGetSystemRoutineAddress (with export-table fallback).  Also
    // discovers the OBJECT_HEADER PointerCount offset by pattern-scanning
    // when the Ob* functions cannot be resolved.  Must be called at
    // PASSIVE_LEVEL (i.e. from Entry before VMX is enabled).
    bool InitObjectFunctions();

    //
    // Returns the total physical memory in bytes, queried from the kernel's
    // PHYSICAL_MEMORY_RANGE list (resolved dynamically at boot).  Zero is
    // returned on failure.
    ULONG64 GetTotalSystemMemory();

    //
    // Parses the export directory of an already-mapped kernel module (e.g.
    // ntoskrnl.exe or hal.dll) to locate an exported function by name.
    // Returns nullptr if the export is not found.
    PVOID GetKernelModuleExport(PVOID moduleBase, const char* exportName);

    //
    // Discovers the OBJECT_HEADER PointerCount offset by disassembling the
    // ObfReferenceObjectWithTag implementation in ntoskrnl.exe.  Returns 0
    // on failure.  This is the fallback path when
    // MmGetSystemRoutineAddress cannot resolve the Ob* functions directly.
    ULONG32 FindReferenceCountOffset();

    //
    // Fills Global::MsrRange01Max / MsrRange2Max / MsrPermissionsMapSize
    // from CPUID Fn8000_000A on the current CPU (Zen 2, 4800H).
    void InitMsrRanges();
    void ReferenceObject(PVOID object);
    void DereferenceObject(PVOID object);

    const SIZE_T PreallocatedPoolSize = 0x1000;
    PVOID GetPreallocatedPool(SIZE_T poolIndex);
}
