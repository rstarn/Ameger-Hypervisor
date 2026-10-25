#pragma once

#include "Defines/ProcessorData.h"

namespace SVM
{
    EXTERN_C void _sgdt(PVOID descriptor);
    EXTERN_C void NTAPI LaunchVM(PVOID hostRsp);

    NTSTATUS CheckSupport();
    void BuildNestedPageTables(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData);
    NTSTATUS ProtectSelf(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData);
    NTSTATUS HideRange(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, ULONG64 virtualBase, SIZE_T size);

    //
    // Transparent-hide support.  GetPageTableEntry() returns the 4 KB NPT leaf
    // entry for a guest physical page (splitting the containing large page
    // first).  RestoreHiddenPage() re-sets Present on a hidden page so the
    // guest's nested page fault resolves transparently.  TrackForRehide() asks
    // the revert scan to put a restored page back to not-present once it is
    // quiet.  Each returns false/no-op when self-hide is compiled out.
    //
    PT_ENTRY_4KB* GetPageTableEntry(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, ULONG64 physical);
    bool RestoreHiddenPage(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, ULONG64 gpa);
    void TrackForRehide(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, PT_ENTRY_4KB* entry);
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