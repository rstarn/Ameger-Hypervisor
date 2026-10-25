#include "../../Core/Global.h" // IWYU pragma: keep

void SVM::HandleGenericSVM(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(guestContext);

    /*
     * VMRUN/VMLOAD/VMSAVE and SKINIT are privileged SVM instructions that
     * must not be usable by the guest.  STGI/CLGI only manipulate GIF, which
     * the host owns; treating them as no-ops keeps guest code that toggles
     * GIF working without letting it affect the host's interrupt window.
     */
    switch (vpData->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_STGI:
    case VMEXIT_CLGI:
        vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
        return;

    case VMEXIT_VMRUN:
    case VMEXIT_VMLOAD:
    case VMEXIT_VMSAVE:
    case VMEXIT_SKINIT:
    default:
        InjectUndefinedOpcodeException(vpData);
        return;
    }
}

void SVM::HandleCPUID(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext)
{
    int registers[4];
    const ULONG leaf = static_cast<ULONG>(vpData->GuestVmcb.StateSaveArea.Rax);

    //
    // ECX is not part of the VMCB state save area: like every GPR other than
    // RAX/RSP, it is saved live by PUSHAQ in the exit stub, so the guest's
    // subleaf comes from the register frame.  (RAX alone is resynchronised
    // from the VMCB because the stub clobbers it before PUSHAQ.)
    //
    const ULONG subleaf = static_cast<ULONG>(guestContext->VpRegs->Rcx);

    //
    // Several leaves are indexed by ECX (4, 7, 0xB, 0xD, 0x1F, 0x8000001E).
    // __cpuid always queries subleaf 0, which makes Windows observe the same
    // cache/topology record for every subleaf; __cpuidex forwards the guest's
    // ECX so each subleaf returns its own data.
    //
    __cpuidex(registers, static_cast<int>(leaf), static_cast<int>(subleaf));

    switch (leaf)
    {
    case CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS:
        //
        // Hide the hypervisor-present bit.  The guest still sees the real
        // CPUID feature set, but not the fact that it is running under SVM.
        //
        registers[2] &= ~static_cast<int>(CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT);
        break;

    case CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX:
        registers[2] &= ~static_cast<int>(CPUID_FN8000_0001_ECX_SVM);
        break;

    case CPUID_SVM_FEATURES:
        //
        // The entire SVM feature leaf is unavailable to the guest: reporting
        // zero is what a CPU with SVM disabled (or no SVM at all) returns.
        //
        registers[0] = 0;
        registers[1] = 0;
        registers[2] = 0;
        registers[3] = 0;
        break;

    default:
        break;
    }

    guestContext->VpRegs->Rax = static_cast<UINT64>(static_cast<UINT32>(registers[0]));
    guestContext->VpRegs->Rbx = static_cast<UINT64>(static_cast<UINT32>(registers[1]));
    guestContext->VpRegs->Rcx = static_cast<UINT64>(static_cast<UINT32>(registers[2]));
    guestContext->VpRegs->Rdx = static_cast<UINT64>(static_cast<UINT32>(registers[3]));
    vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
}
