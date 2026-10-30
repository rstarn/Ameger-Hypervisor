#pragma once

#include "Defines/ProcessorData.h"

namespace SVM
{
    EXTERN_C void _sgdt(PVOID descriptor);
    EXTERN_C void NTAPI LaunchVM(PVOID hostRsp);

    NTSTATUS CheckSupport();
    void BuildNestedPageTables(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData);
    //
    // Resolves this driver's own .text section [VirtualAddress,
    // VirtualAddress + VirtualSize) from its PE headers at Global::DriverBase.
    // Returns false (and logs) when the headers are not a valid PE image or the
    // .text section is missing - ProtectSelf() then falls back to hiding only
    // pool-tagged allocations and never hides .text.
    //
    bool GetDriverTextRange(ULONG64* textBase, SIZE_T* textSize);
    //
    // ProtectSelf() hides this driver's image minus the caller-supplied
    // executable range [textBase, textBase + textSize).  textBase == 0 or
    // textSize == 0 means "no executable range known": the whole image is
    // hidden (legacy behaviour).  HideRange() is the same primitive for an
    // arbitrary guest virtual range; ProtectRange passes 0, 0.
    //
    NTSTATUS ProtectSelf(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, ULONG64 textBase, SIZE_T textSize);
    NTSTATUS HideRange(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, ULONG64 virtualBase, SIZE_T size, ULONG64 textBase, SIZE_T textSize);

    //
    // Transparent-hide support.  GetPageTableEntry() returns the 4 KB NPT leaf
    // entry for a guest physical page.  allowSplit == true may split the
    // containing large page (consuming a preallocated pool page);
    // allowSplit == false never allocates, so the diagnostic/#NPF path cannot
    // exhaust the pool.  TrackForRehide() asks the revert scan to put a
    // restored page back to not-present once it is quiet.  DisableSelfHide()
    // restores every recorded page and stops re-hiding for good (fail open).
    // Each returns false/no-op when self-hide is compiled out.
    //
    PT_ENTRY_4KB* GetPageTableEntry(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, ULONG64 gpa, bool allowSplit);
    //
    // Result of MapGpaOnDemand().
    //
    enum class GpaMapResult
    {
        CannotMap,     // spare pool exhausted, GPA outside 48 bits, or 1 GB-page NPT
        MappedNow,     // this call published the 1 GB region; flush and resume
        AlreadyMapped, // the region was already present; only a stale TLB entry remains
    };

    //
    // Maps the 1 GB guest-physical region containing gpa 1:1 from the
    // boot-time spare PD pool, so a #NPF above the boot-time NPT window (a
    // device BAR, for instance) is resolved instead of re-faulting forever.
    // CannotMap means the fault cannot be fixed this way and the caller must
    // run its unresolved-fault path (flush plus tripwire), so such a fault is
    // never silent.
    //
    GpaMapResult MapGpaOnDemand(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, ULONG64 gpa);
    void TrackForRehide(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, PT_ENTRY_4KB* entry);
    void DisableSelfHide(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData);
    void BuildPermissionMap(PVOID permissionMap);

    //
    // Returns 1 when this processor was already virtualized, 0 when the
    // caller must prepare and launch its VMCB, and -1 when the per-CPU
    // bookkeeping could not be allocated.  The tri-state matters: treating an
    // allocation failure as "already installed" would leave a CPU outside
    // guest mode, so VMMCALL there would #UD and kill the client.
    //
    int CheckAndSetInstalled();
    UINT16 GetSegmentAccessRights(UINT16 segmentSelector, ULONG_PTR gdtBase);
    void PrepareForVirtualization(PVIRTUAL_PROCESSOR_DATA vpData, PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData, const PCONTEXT contextRecord);
    NTSTATUS VirtualizeProcessor(PVOID context);
    void VirtualizeAllProcessors(PVOID);

    //
    // Extracts the segment limit for the given selector by looking up the
    // descriptor in the GDT whose base is gdtBase.  The limit is returned
    // as a flat byte count (granularity already applied).
    ULONG GetSegmentLimit(UINT16 segmentSelector, ULONG_PTR gdtBase);
}