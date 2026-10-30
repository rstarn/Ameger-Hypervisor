#include "../../../Core/Global.h"
#include "../../../Common/HVLogs.h"
#include "../../../SVM/Stealth.h"

void SVM::InjectGeneralProtectionException(const PVIRTUAL_PROCESSOR_DATA vpData)
{
    EVENTINJ event;
    event.AsUInt64 = 0;
    event.Fields.Vector = EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT;
    event.Fields.Type = INTERRUPT_TYPE_HARDWARE_EXCEPTION;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    vpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

/*
 * PR #15: AMD APM vol. 2 (24593, ch. "VMMCALL"/"VMRUN"/"VMLOAD") specifies
 * #UD - not #GP - for these instructions when they are not supported in the
 * current context. Injecting #UD keeps guest code that probes for a
 * hypervisor (or issues these instructions while EFER.SVME is cleared)
 * faulting the way it would on bare metal instead of raising a fatal #GP.
 */
void SVM::InjectUndefinedOpcodeException(const PVIRTUAL_PROCESSOR_DATA vpData)
{
    EVENTINJ event;
    event.AsUInt64 = 0;
    event.Fields.Vector = EXCEPTION_VECTOR_UNDEFINED_OPCODE;
    event.Fields.Type = INTERRUPT_TYPE_HARDWARE_EXCEPTION;
    event.Fields.ErrorCodeValid = 0;
    event.Fields.Valid = 1;
    vpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

/*void SVM::InjectPageFaultException(const PVIRTUAL_PROCESSOR_DATA vpData, const ULONG64 address)
{
    // https://wiki.osdev.org/Exceptions#Page_Fault
    EVENTINJ event;
    event.AsUInt64 = 0;
    event.Fields.Vector = EXCEPTION_VECTOR_PAGE_FAULT;
    event.Fields.Type = INTERRUPT_TYPE_HARDWARE_EXCEPTION;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Present = 1;

    PAGE_FAULT_EXCEPTION errorCode;
    errorCode.AsUInt = 0;
    errorCode.UserModeAccess = 1;

    event.Fields.ErrorCode = errorCode.AsUInt;

    vpData->GuestVmcb.StateSaveArea.Cr2 = address;

    vpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}*/

bool SVM::IsInUserland(PVIRTUAL_PROCESSOR_DATA vpData)
{
    //
    // User/kernel boundary is not a constant: Win11 24H2 uses 64-bit user
    // space, so the split sits at MmHighestUserAddress, not the old 48-bit
    // 0x7FFFFFFEFFFF.
    return vpData->GuestVmcb.StateSaveArea.Cpl == 3 && vpData->GuestVmcb.ControlArea.NRip <= Global::HighestUserAddress;
}

EXTERN_C void SVM::HandleExit(PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_REGISTERS guestRegisters)
{
    GUEST_CONTEXT guestContext;
    guestContext.VpRegs = guestRegisters;

    //
    // No VMLOAD here.  #VMEXIT has already reloaded the host state (including
    // RIP, RSP, RAX and RFLAGS) from the VM_HSAVE_PA area, which is why
    // LaunchVM resumes at the instruction after VMRUN with the host stack
    // intact.  VMLOAD loads that same subset from a VMCB, so loading
    // HostVmcb here would restore the stale snapshot taken by
    // PrepareForVirtualization() - RIP/RSP/RAX from the virtualization
    // thread - and corrupt the exit handler's own frame.
    //

    guestRegisters->Rax = vpData->GuestVmcb.StateSaveArea.Rax;

    vpData->HostStackLayout.TrapFrame.Rsp = vpData->GuestVmcb.StateSaveArea.Rsp;
    vpData->HostStackLayout.TrapFrame.Rip = vpData->GuestVmcb.ControlArea.NRip;

    //
    // SVM::ProtectSelf() rewrites NPT entries that all vCPUs share.  It sets
    // TlbControl in every registered VMCB, but a vCPU that was already in
    // guest mode when the rewrite happened may have read its control area
    // before that store landed.  The shared generation counter is the
    // backstop: the first exit after a rewrite re-arms TlbControl, and the
    // store is consumed by the VMRUN that follows this handler.
    //
    // The slot is indexed by the system-wide processor index, matching how
    // Global::VirtualizedCpus / shared->NptFlushSeen were allocated.  Until
    // ProtectSelf() runs the generation is zero and this costs one load.
    //
    const PSHARED_VIRTUAL_PROCESSOR_DATA sharedData = vpData->HostStackLayout.SharedVpData;
    const ULONG exitCode = static_cast<ULONG>(vpData->GuestVmcb.ControlArea.ExitCode);

    //
    // System-wide processor index, computed once per exit: both the flush
    // generation check and the nested-page-fault bookkeeping below key off
    // it.
    //
    ULONG processorIndex = 0;
    if (sharedData)
    {
        PROCESSOR_NUMBER processorNumber;
        KeGetCurrentProcessorNumberEx(&processorNumber);
        processorIndex = KeGetProcessorIndexFromNumber(&processorNumber);
    }

    //
    // TLB_CONTROL is a one-shot command that the next VMRUN consumes, and
    // hardware does not document clearing the field afterwards.  Reset it at
    // the top of every exit so a value armed by an earlier handler (or by
    // HideRange() on this VMCB) cannot make every subsequent VMRUN flush
    // the entire TLB.  The paths that genuinely need a flush - the
    // generation check below, the NPF restore, the hide commands - re-arm
    // it after this point.
    //
    vpData->GuestVmcb.ControlArea.TlbControl = 0;
    SVM::MarkVmcbDirty(vpData->GuestVmcb.ControlArea);

    if (sharedData && exitCode != VMEXIT_NPF)
    {
        //
        // Any exit other than a nested page fault means the guest made
        // progress, so this CPU's run of unresolved NPFs is over.
        //
        InterlockedExchange(&sharedData->NpfUnresolvedRun[processorIndex < 64 ? processorIndex : 0], 0);
    }

    if (sharedData && sharedData->NptFlushGeneration != 0)
    {
        if (sharedData->NptFlushSeen &&
            processorIndex < Global::VirtualizedCpuCount &&
            sharedData->NptFlushSeen[processorIndex] != sharedData->NptFlushGeneration)
        {
            sharedData->NptFlushSeen[processorIndex] = sharedData->NptFlushGeneration;

            InterlockedExchange(reinterpret_cast<volatile LONG*>(&vpData->GuestVmcb.ControlArea.TlbControl), 1);
            SVM::MarkVmcbDirty(vpData->GuestVmcb.ControlArea);
        }
    }

    //
    // Transparent-hide revert.  Count this VMEXIT and, sparsely, put recently
    // restored pages that have gone quiet back to not-present.  This runs on
    // the hottest path, so the scan is amortized (a window every
    // NPT_REHIDE_SCAN_INTERVAL exits, a handful of slots each) and every
    // failure mode degrades to "the page stays mapped" - never a crash.  A hot
    // page keeps getting re-restored before its grace elapses, so it never
    // reverts while actively executed.
    //
    const LONG exitCount = sharedData ? InterlockedIncrement(&sharedData->NptExitCounter) : 0;
    if (sharedData && sharedData->NptRehideEnabled &&
        exitCount > 0 && (exitCount % NPT_REHIDE_SCAN_INTERVAL) == 0)
    {
        bool reHidden = false;

        const LONG window = (exitCount / NPT_REHIDE_SCAN_INTERVAL) & (NPT_REHIDE_CAPACITY - 1);
        for (ULONG scan = 0; scan < NPT_REHIDE_SCAN; scan++)
        {
            //
            // Re-check the global flag per slot: DisableSelfHide() may have
            // run on another CPU between the gate above and this store, and
            // it has already restored everything.
            //
            if (!sharedData->NptRehideEnabled)
                break;

            const LONG slot = (window + scan) & (NPT_REHIDE_CAPACITY - 1);
            PT_ENTRY_4KB* const hiddenEntry = sharedData->NptRehide[slot];
            if (!hiddenEntry)
                continue;

            if (exitCount - sharedData->NptRehideRestoreExit[slot] < NPT_REHIDE_GRACE)
                continue;

            InterlockedExchange64(reinterpret_cast<volatile LONGLONG*>(&hiddenEntry->AsUInt64),
                hiddenEntry->AsUInt64 & ~1ULL);
            sharedData->NptRehide[slot] = nullptr;
            reHidden = true;
        }

        //
        // This CPU's next VMRUN is flushed by the TlbControl store at the top
        // of the *next* exit, but the other vCPUs may still translate the
        // page through a cached entry.  Bumping the generation makes each of
        // them arm its own TlbControl at its next exit.
        //
        if (reHidden)
            InterlockedIncrement(&sharedData->NptFlushGeneration);
    }

    switch (vpData->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_MSR:
#if HYPERVISOR_STEALTH
        if (Stealth::HandleMsrAccess(vpData, &guestContext))
            break;
#endif
        HandleMSRAccess(vpData, &guestContext);
        break;
    case VMEXIT_VMRUN:
    case VMEXIT_VMLOAD:
    case VMEXIT_VMSAVE:
    case VMEXIT_STGI:
    case VMEXIT_CLGI:
    case VMEXIT_SKINIT:
        HandleGenericSVM(vpData, &guestContext);
        break;
    case VMEXIT_CPUID:
#if HYPERVISOR_STEALTH
        if (Stealth::HandleCpuidSpoof(vpData, &guestContext))
            break;
#endif
        HandleCPUID(vpData, &guestContext);
        break;
    case VMEXIT_VMMCALL:
        HandleVMCall(vpData, &guestContext);
        break;
    case VMEXIT_NPF:
        //
        // BuildNestedPageTables maps guest-physical space 1:1 with full
        // permissions (P=W=S=1, NX=0): the whole 48-bit space when the CPU
        // has 1 GB nested pages, or the RAM range plus a 1 TB floor when the
        // 2 MB fallback is in use (see ComputeMappedGpaEnd).  Two things can
        // fault inside that window: a page HideRange() made not-present, and
        // a GPA above the boot-time window (a device BAR).  Both are resolved
        // here without injecting anything: restore or map, flush this CPU's
        // TLB at the next VMRUN, and resume the faulting instruction.  NRip is
        // left as-is, so the CPU re-executes the access against the restored
        // page and the guest never observes a fault.
        //
        // The lookup runs with allowSplit == false: the diagnostic path must
        // never allocate a split table.  Doing so used to burn the fixed
        // preallocated pool on unrelated faults until genuine hidden pages
        // could no longer be reached at all.
        //
        // NOTHING is ever injected from this path.  Injecting #PF from a
        // #NPF is the one mechanism this driver has that reliably
        // hard-freezes the machine: the CPU pushes our error code, but CR2
        // keeps whatever stale value it already held, so the guest's
        // page-fault handler resolves nothing, returns, and the same
        // instruction faults again - a livelock with no bugcheck, spinning
        // that core between VMRUN and #NPF forever.
        //
        {
            const ULONG64 gpa = vpData->GuestVmcb.ControlArea.ExitInfo2;
            const ULONG slot = processorIndex < 64 ? processorIndex : 0;

            Hypervisor::LogNum("HandleExit: NPF gpa", gpa);

            PT_ENTRY_4KB* entry = sharedData ? SVM::GetPageTableEntry(sharedData, gpa, false) : nullptr;

            //
            // A GPA above the boot-time window has no PDPTE at all, so there
            // is no leaf to inspect.  Map the whole 1 GB region from the
            // spare PD pool and resume: the region is now covered by 2 MB
            // large pages, which is exactly what the boot-time tree uses.
            // If the pool cannot supply a page, fall through to the
            // unresolved-fault tripwire rather than re-faulting silently.
            //
            if (!entry && sharedData)
            {
                const SVM::GpaMapResult mapResult = SVM::MapGpaOnDemand(sharedData, gpa);

                if (mapResult != SVM::GpaMapResult::CannotMap)
                {
                    if (mapResult == SVM::GpaMapResult::MappedNow)
                    {
                        InterlockedExchange(&sharedData->NpfUnresolvedRun[slot], 0);
                        InterlockedExchange(&sharedData->NpfStaleStrikes[slot], 0);
                        Hypervisor::Log("NPF: region mapped on demand");
                    }
                    else if (InterlockedIncrement(&sharedData->NpfUnresolvedRun[slot]) > NPF_UNRESOLVED_LIMIT)
                    {
                        //
                        // The region is present in the NPT and the TLB is
                        // flushed on every one of these faults, yet the same
                        // access keeps faulting: there is nothing left to fix.
                        //
                        KeBugCheckEx(INVALID_DRIVER_HANDLE,
                            static_cast<ULONG64>('NPF2'),
                            gpa,
                            vpData->GuestVmcb.StateSaveArea.Rip,
                            vpData->GuestVmcb.ControlArea.ExitInfo1);
                    }

                    vpData->GuestVmcb.ControlArea.EventInj = 0;
                    InterlockedExchange(reinterpret_cast<volatile LONG*>(&vpData->GuestVmcb.ControlArea.TlbControl), 1);
                    SVM::MarkVmcbDirty(vpData->GuestVmcb.ControlArea);
                    return;
                }
            }

            if (entry)
            {
                if ((entry->AsUInt64 & 1) == 0)
                {
                    //
                    // HideRange() cleared only the Present bit, leaving the
                    // real PFN and Write flag intact, so restoring is one
                    // atomic Present set.  TrackForRehide() schedules the
                    // page for the amortized revert scan and counts the
                    // restore against the sticky-restore budget.
                    //
                    InterlockedExchange64(reinterpret_cast<volatile LONGLONG*>(&entry->AsUInt64), entry->AsUInt64 | 1);
                    SVM::TrackForRehide(sharedData, entry);

                    InterlockedExchange(&sharedData->NpfUnresolvedRun[slot], 0);
                    InterlockedExchange(&sharedData->NpfStaleStrikes[slot], 0);

                    Hypervisor::Log("NPF restored");
                }
                else
                {
                    //
                    // The entry is already present.  That used to be a silent
                    // fixed point: the handler did nothing, the CPU refaulted
                    // on the same instruction, and after 1000 unresolved
                    // faults the tripwire bugchecked.  A few of these are
                    // normal walk-cache races, so flush unconditionally and
                    // count them; a long run means the CPU cannot make
                    // progress, and self-hide fails open instead of
                    // bugchecking.
                    //
                    const LONG strikes = InterlockedIncrement(&sharedData->NpfStaleStrikes[slot]);

                    Hypervisor::LogNum("NPF already present, gpa", gpa);

                    if (strikes > NPF_STALE_STRIKE_LIMIT)
                    {
                        SVM::DisableSelfHide(sharedData);
                        InterlockedExchange(&sharedData->NpfStaleStrikes[slot], 0);
                    }
                }

                //
                // TLB_CONTROL = 1 is a full flush of the TLB *and* the nested
                // page translations (AMD APM vol. 2, "TLB Control"): it is the
                // only value that invalidates NPT-derived entries, and it is
                // required even when the entry was already present, because
                // the CPU's walk cache may still hold the stale encoding.
                //
                vpData->GuestVmcb.ControlArea.EventInj = 0;
                InterlockedExchange(reinterpret_cast<volatile LONG*>(&vpData->GuestVmcb.ControlArea.TlbControl), 1);
                SVM::MarkVmcbDirty(vpData->GuestVmcb.ControlArea);

                return;
            }

            //
            // No entry and no region to map: either the spare PD pool is
            // exhausted or the GPA is outside the 48-bit space.  The hide is
            // no longer defensible - restore everything and stop re-hiding,
            // then resume without injection.  A genuinely stuck RIP keeps
            // accumulating in NpfUnresolvedRun and the tripwire below turns
            // it into a diagnosable bugcheck instead of a silent freeze.
            //
            SVM::DisableSelfHide(sharedData);

            if (sharedData &&
                InterlockedIncrement(&sharedData->NpfUnresolvedRun[slot]) > NPF_UNRESOLVED_LIMIT)
            {
                Hypervisor::Log("HandleExit: NPF stuck, bugcheck");

                KeBugCheckEx(INVALID_DRIVER_HANDLE,
                    static_cast<ULONG64>('NPF1'),
                    gpa,
                    vpData->GuestVmcb.StateSaveArea.Rip,
                    vpData->GuestVmcb.ControlArea.ExitInfo1);
            }

            Hypervisor::Log("HandleExit: NPF unresolvable, resuming");

            vpData->GuestVmcb.ControlArea.TlbControl = 1;
            SVM::MarkVmcbDirty(vpData->GuestVmcb.ControlArea);
        }
        break;
    case VMEXIT_SHUTDOWN:
        //
        // A shutdown exit means the guest triple-faulted.  EventInj has no
        // encoding for shutdown (type only covers interrupt / NMI / exception /
        // software-interrupt events), and re-injecting an exception into a VMCB
        // whose guest could not dispatch the previous one would just re-enter
        // this handler forever.  There is no safe injection here, so fall
        // through to the unrecoverable-exit path below.
        //
    default:
        Hypervisor::Log("HandleExit: unrecoverable exit -> bugcheck");

        KeBugCheckEx(INVALID_DRIVER_HANDLE, IsInUserland(vpData), vpData->GuestVmcb.StateSaveArea.Rip, vpData->GuestVmcb.ControlArea.ExitCode, vpData->GuestVmcb.ControlArea.ExitInfo1);
    }

    vpData->GuestVmcb.StateSaveArea.Rax = guestContext.VpRegs->Rax;
}