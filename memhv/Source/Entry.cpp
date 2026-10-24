#include "Global.h"

EXTERN_C bool Utils::GetOffsets()
{
    UNICODE_STRING stringPsGetProcessId;
    RtlInitUnicodeString(&stringPsGetProcessId, L"PsGetProcessId");

    BYTE* routinePsGetProcessId = static_cast<BYTE*>(MmGetSystemRoutineAddress(&stringPsGetProcessId));
    if (!routinePsGetProcessId)
        return false;

    //
    // PsGetProcessId proc near
    // mov rax, [rcx + <disp32>]
    // 48 8B 81 (xx xx xx xx)
    // VOID* UniqueProcessId;
    // struct _LIST_ENTRY ActiveProcessLinks;
    //
    // Validate the opcode before trusting the displacement: if Microsoft
    // ever changes the prologue the defaults stay untouched instead of
    // loading garbage into the offsets.
    if (routinePsGetProcessId[0] != 0x48 ||
        routinePsGetProcessId[1] != 0x8B ||
        routinePsGetProcessId[2] != 0x81)
    {
        return false;
    }

    const UINT32 uniqueProcessId =
        *reinterpret_cast<UINT32*>(routinePsGetProcessId + 3);

    //
    // Sanity-check the resolved offset: EPROCESS is a few kilobytes and
    // both fields sit well inside it.
    if (uniqueProcessId == 0 || uniqueProcessId > 0x1000)
        return false;

    Global::Offsets::UniqueProcessId = uniqueProcessId;
    Global::Offsets::ActiveProcessLinks = uniqueProcessId + 8;

    //
    // DirectoryTableBase: instead of trusting a hardcoded offset, derive it
    // from this exact kernel build. Attach to the always-alive System
    // process, read the CR3 the CPU is actually running on, then scan the
    // EPROCESS image for the field holding that same physical page. AMD does
    // not use KVA-shadow CR3 flipping, so the attached CR3 is the process
    // directory base itself; PCID bits are masked out.
    //
    const PEPROCESS systemProcess = PsInitialSystemProcess;
    if (systemProcess)
    {
        KAPC_STATE apcState;
        KeStackAttachProcess(systemProcess, &apcState);

        const ULONG64 liveDirectoryBase = __readcr3() & 0x000FFFFFFFFFF000;

        KeUnstackDetachProcess(&apcState);

        if (liveDirectoryBase)
        {
            const PULONG64 fields = reinterpret_cast<PULONG64>(systemProcess);

            for (UINT32 offset = 0; offset < 0x800; offset += sizeof(ULONG64))
            {
                const ULONG64 value = fields[offset / sizeof(ULONG64)];

                if (value != 0 &&
                    (value & 0x000FFFFFFFFFF000) == liveDirectoryBase &&
                    value < 0x0000800000000000) // physical addresses stay far below the canonical split
                {
                    Global::Offsets::DirectoryTableBase = offset;
                    break;
                }
            }
        }
    }

    return true;
}

NTSTATUS PreallocatePools()
{
    for (UINT32 i = 0; i < ARRAYSIZE(Global::PreallocatedPools); i++)
    {
        Global::PreallocatedPools[i] = Utils::AllocatePageAligned(Utils::PreallocatedPoolSize);
        if (!Global::PreallocatedPools[i])
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS Entry()
{
    //
    // Resolve the EPROCESS layout for this exact kernel build first, so
    // every later consumer (process walk, CR3 resolution) uses dynamic
    // offsets instead of hardcoded ones.
    //
    if (!Utils::GetOffsets())
        return STATUS_PROCEDURE_NOT_FOUND;

    //
    // Read the user/kernel boundary from this kernel's MmHighestUserAddress
    // export (64-bit user space on this Win11 24H2 build).
    //
    Global::HighestUserAddress = MmHighestUserAddress;

    //
    // Resolve the MSR permission-map geometry for this CPU from CPUID
    // Fn8000_000A (Zen 2, Ryzen 7 4800H).
    //
    Utils::InitMsrRanges();

    if (!Memory::PreparePages())
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = SVM::CheckSupport();
    if (!NT_SUCCESS(status))
        return status;

    status = PreallocatePools();
    if (!NT_SUCCESS(status))
        return status;

    Global::BlankPage = Utils::AllocatePageAligned(PAGE_SIZE);
    if (!Global::BlankPage)
        return STATUS_INSUFFICIENT_RESOURCES;

    HANDLE threadHandle;
    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, SVM::VirtualizeAllProcessors, nullptr);
    if (!NT_SUCCESS(status))
        return status;

    return status;
}