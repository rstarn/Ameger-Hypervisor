#include "../../Global.h"
#include "../../HVLog.h"

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

EXTERN_C bool SVM::HandleExit(PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_REGISTERS guestRegisters)
{
    GUEST_CONTEXT guestContext;
    guestContext.VpRegs = guestRegisters;
    guestContext.ExitVm = false;

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
    SVM::MarkControlAreaDirty(vpData->GuestVmcb.ControlArea);

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
            SVM::MarkControlAreaDirty(vpData->GuestVmcb.ControlArea);
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
    if (sharedData && exitCount > 0 && (exitCount % NPT_REHIDE_SCAN_INTERVAL) == 0)
    {
        const LONG window = (exitCount / NPT_REHIDE_SCAN_INTERVAL) & (NPT_REHIDE_CAPACITY - 1);
        for (ULONG scan = 0; scan < NPT_REHIDE_SCAN; scan++)
        {
            const LONG slot = (window + scan) & (NPT_REHIDE_CAPACITY - 1);
            PT_ENTRY_4KB* const hiddenEntry = sharedData->NptRehide[slot];
            if (!hiddenEntry)
                continue;

            if (exitCount - sharedData->NptRehideRestoreExit[slot] < NPT_REHIDE_GRACE)
                continue;

            InterlockedExchange64(reinterpret_cast<volatile LONGLONG*>(&hiddenEntry->AsUInt64),
                hiddenEntry->AsUInt64 & ~1ULL);
            sharedData->NptRehide[slot] = nullptr;
        }
    }

    switch (vpData->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_MSR:
        HandleMSRAccess(vpData, &guestContext);
        break;
    case VMEXIT_VMRUN:
    case VMEXIT_VMLOAD:
    case VMEXIT_VMSAVE:
        HandleGenericSVM(vpData, &guestContext);
        break;
    case VMEXIT_VMMCALL:
        HandleVMCall(vpData, &guestContext);
        break;
    case VMEXIT_NPF:
        //
        // BuildNestedPageTables maps the whole physical space 1:1 with full
        // permissions (P=W=S=1, NX=0), so by construction the only nested
        // page faults possible on this VMCB are the pages HideRange() made
        // not-present.  Resolve them transparently: re-set Present, flush
        // this CPU's TLB at the next VMRUN, and resume the faulting
        // instruction.  No event is injected and NRip is left as-is, so the
        // CPU re-executes the access against the restored page and the
        // guest never observes a fault.
        //
        // NOTHING is ever injected from this path.  Injecting #PF from a
        // #NPF is the one mechanism this driver has that reliably
        // hard-freezes the machine: the CPU pushes our error code, but CR2
        // keeps whatever stale value it already held, so the guest's
        // page-fault handler resolves nothing, returns, and the same
        // instruction faults again - a livelock with no bugcheck, spinning
        // that core between VMRUN and #NPF forever.  A fault that cannot be
        // attributed to a hidden page is simply resumed (walk races are
        // transient and self-resolving); a genuinely stuck RIP accumulates
        // in NpfUnresolvedRun and the tripwire below turns it into a
        // diagnosable bugcheck instead of a silent freeze.
        //
        {
            const ULONG64 gpa = vpData->GuestVmcb.ControlArea.ExitInfo2;

            HV::LogNum("HandleExit: NPF gpa", gpa);

            PT_ENTRY_4KB* entry = sharedData ? SVM::GetPageTableEntry(sharedData, gpa) : nullptr;

            if (entry && entry->Present == 0)
            {
                //
                // HideRange() cleared only the Present bit, leaving the real
                // PFN and Write flag intact, so restoring is one atomic
                // Present set.
                //
                InterlockedExchange64(reinterpret_cast<volatile LONGLONG*>(&entry->AsUInt64), entry->AsUInt64 | 1);
                SVM::TrackForRehide(sharedData, entry);

                //
                // Force a clean NPT TLB on this CPU so a stale cached entry
                // cannot re-fault the same page in a storm.
                //
                InterlockedExchange(reinterpret_cast<volatile LONG*>(&vpData->GuestVmcb.ControlArea.TlbControl), 1);
                SVM::MarkControlAreaDirty(vpData->GuestVmcb.ControlArea);

                vpData->GuestVmcb.ControlArea.EventInj = 0;
                SVM::MarkControlAreaDirty(vpData->GuestVmcb.ControlArea);

                InterlockedExchange(&sharedData->NpfUnresolvedRun[processorIndex < 64 ? processorIndex : 0], 0);

                HV::Log("HandleExit: NPF restored");

                return false;
            }

            //
            // Not attributable to a hidden page: either the entry is already
            // present (a transient walk race - this NPT cannot produce
            // permission faults by construction) or the split table could
            // not be reached.  Resume without injection and count the run.
            // A long run means the RIP is genuinely stuck: fail loudly with
            // a crash dump rather than freezing the machine invisibly.
            //
            if (sharedData &&
                InterlockedIncrement(&sharedData->NpfUnresolvedRun[processorIndex < 64 ? processorIndex : 0]) > 1000)
            {
                HV::Log("HandleExit: NPF stuck, bugcheck");

                KeBugCheckEx(INVALID_DRIVER_HANDLE,
                    static_cast<ULONG64>('NPF1'),
                    gpa,
                    vpData->GuestVmcb.StateSaveArea.Rip,
                    vpData->GuestVmcb.ControlArea.ExitInfo1);
            }

            HV::Log("HandleExit: NPF unresolvable, resuming");
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
        HV::Log("HandleExit: unrecoverable exit -> bugcheck");

        KeBugCheckEx(INVALID_DRIVER_HANDLE, IsInUserland(vpData), vpData->GuestVmcb.StateSaveArea.Rip, vpData->GuestVmcb.ControlArea.ExitCode, vpData->GuestVmcb.ControlArea.ExitInfo1);
    }

    if (guestContext.ExitVm)
    {
        guestContext.VpRegs->Rax = reinterpret_cast<UINT64>(vpData) & MAXUINT32;
        guestContext.VpRegs->Rbx = vpData->GuestVmcb.ControlArea.NRip;
        guestContext.VpRegs->Rcx = vpData->GuestVmcb.StateSaveArea.Rsp;
        guestContext.VpRegs->Rdx = reinterpret_cast<UINT64>(vpData) >> 32;

        __svm_vmload(MmGetPhysicalAddress(&vpData->GuestVmcb).QuadPart);

        _disable();
        __svm_stgi();

        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) & ~EFER_SVME);
        __writeeflags(vpData->GuestVmcb.StateSaveArea.Rflags);

        return true;
    }

    vpData->GuestVmcb.StateSaveArea.Rax = guestContext.VpRegs->Rax;

    return false;
}