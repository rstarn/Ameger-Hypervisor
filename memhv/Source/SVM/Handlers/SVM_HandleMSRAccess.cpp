#include "../../Global.h" // IWYU pragma: keep

FORCEINLINE bool CheckRange(const ULONG64 input, const ULONG64 rangeStart, const ULONG64 rangeEnd)
{
    if (input >= rangeStart && input <= rangeEnd)
        return true;

    return false;
}

void SVM::HandleMSRAccess(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext)
{
    const UINT32 msr = guestContext->VpRegs->Rcx & MAXUINT32;
    const BOOLEAN writeAccess = (vpData->GuestVmcb.ControlArea.ExitInfo1 != 0);

    ULARGE_INTEGER value;
    if (msr == IA32_MSR_EFER)
    {
        if (writeAccess)
        {
            value.LowPart = guestContext->VpRegs->Rax & MAXUINT32;
            value.HighPart = guestContext->VpRegs->Rdx & MAXUINT32;
            value.QuadPart |= EFER_SVME;

            vpData->GuestVmcb.StateSaveArea.Efer = value.QuadPart;
        }
        else
        {
            value.QuadPart = __readmsr(msr);
            value.QuadPart &= ~EFER_SVME;
            guestContext->VpRegs->Rax = value.LowPart;
            guestContext->VpRegs->Rdx = value.HighPart;
        }
    }
    else if (msr == SVM_MSR_VM_CR || msr == SVM_MSR_VM_HSAVE_PA)
    {
        //
        // The hypervisor's own control MSRs are never forwarded to the CPU:
        // a read of VM_HSAVE_PA would hand the guest the physical address of
        // the host state save area, and VM_CR exposes SVM state (SVMDIS).
        // Reads return zero - what an idle machine shows - and writes are
        // silently ignored, so a guest trying to set VM_CR.SVMDIS gets
        // nothing, not even a fault that reveals an intercept.  EFER reads
        // above are masked the same way (SVME cleared).
        //
        if (!writeAccess)
        {
            guestContext->VpRegs->Rax = 0;
            guestContext->VpRegs->Rdx = 0;
        }
    }
    else if (Utils::CheckMSR(msr))
    {
        if (writeAccess)
        {
            value.LowPart = guestContext->VpRegs->Rax & MAXUINT32;
            value.HighPart = guestContext->VpRegs->Rdx & MAXUINT32;
            __writemsr(msr, value.QuadPart);
        }
        else
        {
            value.QuadPart = __readmsr(msr);
            guestContext->VpRegs->Rax = value.LowPart;
            guestContext->VpRegs->Rdx = value.HighPart;
        }
    }
    else
    {
        //
        // Not whitelisted: emulate instead of faulting.  Every MSR outside
        // the four MSRPM ranges exits here regardless of the permission map
        // (AMD APM, "MSR Intercepts"), and Windows probes exactly such MSRs
        // during normal operation - WHEA's corrected-machine-check polling
        // (HalpCmcPollProcessor -> HalpWheaNativeReadMsr) reads candidate
        // MSRs that do not exist and relies on the access failing quietly.
        // Injecting #GP here escaped the caller's exception handling and
        // killed the thread (bugcheck 0x7E, STATUS_PRIVILEGED_INSTRUCTION).
        //
        // So do what the production hypervisors do (KVM, Hyper-V): a read of
        // an unimplemented MSR returns zero and a write is ignored, and the
        // instruction is skipped.  No exception is ever injected from this
        // handler, which is also the least observable behaviour: a probe
        // cannot distinguish this MSR space from a machine that simply does
        // not implement the MSR.
        //
        if (!writeAccess)
        {
            guestContext->VpRegs->Rax = 0;
            guestContext->VpRegs->Rdx = 0;
        }
    }

    vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
}