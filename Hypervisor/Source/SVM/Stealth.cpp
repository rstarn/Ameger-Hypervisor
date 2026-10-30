#include "../Core/Global.h"
#include "../Common/HVLogs.h"

namespace Stealth
{
    namespace
    {
        //
        // Hypervisor CPUID range (Intel hypervisor feature leaves).  A guest
        // reading any leaf in 0x40000000-0x4FFFFFFF gets zero, which is what a
        // bare-metal CPU that does not implement the hypervisor interface
        // returns.
        //
        constexpr UINT32 CPUIID_HV_RANGE_START = 0x40000000;
        constexpr UINT32 CPUIID_HV_RANGE_END = 0x4FFFFFFF;

        //
        // AMD APM "MSR Intercepts": the MSRPM is 8 KB of four 2 KB ranges.
        // The performance-counter MSRs live in the second range (0xC0000000-
        // 0xC0001FFF, map offset 0x800 bytes).
        //
        constexpr UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
        constexpr UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;
        constexpr UINT32 BITS_PER_MSR = 2;

        constexpr UINT32 IA32_MSR_PERF_CTL = 0xc000009f;
        constexpr UINT32 IA32_MSR_PERF_GLOBAL_CTL = 0xc000038f;

        bool IsHypervisorCpuid(const UINT32 leaf)
        {
            return leaf >= CPUIID_HV_RANGE_START && leaf <= CPUIID_HV_RANGE_END;
        }

        bool IsStealthMsr(const UINT32 msr)
        {
            //
            // EFER is deliberately NOT here: it has a single, validated
            // implementation in SVM::HandleMSRAccess (reserved-bit and
            // LME/LMA checks, 64-bit RAX:RDX handling, SVME forced in the
            // VMCB).  A second, laxer EFER path in this file used to store
            // the guest's low 32 bits verbatim and drop RDX entirely, which
            // let the guest clear LME or set a reserved bit and made the next
            // VMRUN fail with an invalid guest state.
            //
            return msr == IA32_MSR_PERF_CTL || msr == IA32_MSR_PERF_GLOBAL_CTL ||
                msr == MSR_VM_CR || msr == MSR_VM_HSAVE_PA;
        }

        // Clamps the vCPU's system-wide processor index into the allocated
        // per-CPU array bounds (diagnostic accuracy only).
        ULONG CpuSlot(const SVM::PVIRTUAL_PROCESSOR_DATA vpData)
        {
            const ULONG64 cpuIndex = static_cast<ULONG64>(vpData->HostStackLayout.ProcessorIndex);
            const ULONG count = Global::VirtualizedCpuCount ? Global::VirtualizedCpuCount : 1;

            return (cpuIndex < count) ? static_cast<ULONG>(cpuIndex) : 0;
        }
    }

    void ConfigureCpuidSpoofing()
    {
        //
        // The CPUID intercept bit (INTERCEPT_MISC1_CPUID) is already armed in
        // the VMCB control area during boot (see Entry / VirtualizeProcessor);
        // this records that the spoofing table is active.  Leaves 0x1 and
        // 0x80000001 are masked by the existing HandleCPUID; the hypervisor
        // range (0x40000000-0x4FFFFFFF) is handled by HandleCpuidSpoof().
        //
        Hypervisor::Log("Stealth: CPUID spoofing armed");
    }

    void ConfigureMsrIntercepts(const SVM::PSHARED_VIRTUAL_PROCESSOR_DATA sharedData)
    {
        //
        // Layer the performance-counter MSR intercept bits on top of what
        // BuildPermissionMap already set for EFER / VM_CR / VM_HSAVE_PA.
        //
        if (!sharedData->MsrPermissionsMap || !Global::MsrPermissionsMapSize)
            return;

        RTL_BITMAP bitmapHeader;
        RtlInitializeBitMap(&bitmapHeader, static_cast<PULONG>(sharedData->MsrPermissionsMap),
            static_cast<ULONG>(Global::MsrPermissionsMapSize * CHAR_BIT));

        const ULONG perfCtlOffset = SECOND_MSRPM_OFFSET + (IA32_MSR_PERF_CTL - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
        const ULONG perfGlobalOffset = SECOND_MSRPM_OFFSET + (IA32_MSR_PERF_GLOBAL_CTL - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;

        //
        // Both bits of each 2-bit pair are set (LSB read, MSB write) so reads
        // and writes alike exit to the handler; HandleMsrAccess() answers with
        // zero, matching a CPU that simply does not implement these MSRs.
        //
        RtlSetBits(&bitmapHeader, perfCtlOffset, 2);
        RtlSetBits(&bitmapHeader, perfGlobalOffset, 2);

        Hypervisor::Log("Stealth: perf-counter MSR intercepts armed");
    }

    bool HandleCpuidSpoof(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
    {
        const UINT32 leaf = static_cast<UINT32>(vpData->GuestVmcb.StateSaveArea.Rax);

        if (!IsHypervisorCpuid(leaf))
            return false; // defer to the existing HandleCPUID (0x1 / 0x80000001 / everything else)

        //
        // The hypervisor CPUID range returns zero in every result register,
        // which is indistinguishable from a bare-metal CPU without the
        // hypervisor interface.  NRip advances past the CPUID instruction.
        //
        guestContext->VpRegs->Rax = 0;
        guestContext->VpRegs->Rbx = 0;
        guestContext->VpRegs->Rcx = 0;
        guestContext->VpRegs->Rdx = 0;
        vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
        return true;
    }

    bool HandleMsrAccess(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
    {
        const UINT32 msr = static_cast<UINT32>(guestContext->VpRegs->Rcx);

        if (!IsStealthMsr(msr))
            return false; // whitelisted MSRs stay with the existing handler

        const BOOLEAN writeAccess = (vpData->GuestVmcb.ControlArea.ExitInfo1 != 0);

        if (msr == MSR_VM_CR)
        {
            const ULONG slot = CpuSlot(vpData);
            const UINT64 SVMDIS = (1ULL << 4); // bit 4: "SVM disabled"
            const UINT64 LOCK = (1ULL << 5);   // bit 5: only this bit is honored

            if (!writeAccess)
            {
                //
                // Read returns "SVM disabled": SVMDIS set, all other bits zero
                // except the guest's LOCK bit, preserved from the per-CPU tracked
                // value (initialized to (1 << 4) at virtualize time).  A read
                // after a write therefore returns the same spoofed value.
                //
                const UINT64 tracked = Global::SpoofedVmCr ? Global::SpoofedVmCr[slot] : SVMDIS;
                guestContext->VpRegs->Rax = SVMDIS | (tracked & LOCK);
                guestContext->VpRegs->Rdx = 0;
            }
            else
            {
                const UINT64 value = static_cast<UINT64>(guestContext->VpRegs->Rax) & MAXUINT32;

                //
                // Only the LOCK bit may be set; ignore every other bit.  Update
                // the per-CPU tracked value so a later read returns the same value.
                //
                const UINT64 spoofed = SVMDIS | (value & LOCK);
                if (Global::SpoofedVmCr)
                    Global::SpoofedVmCr[slot] = spoofed;
            }

            vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
            return true;
        }

        if (msr == MSR_VM_HSAVE_PA)
        {
            //
            // Read returns 0/0; the write is ignored entirely (no physical
            // address of the host state save area is ever exposed).
            //
            if (!writeAccess)
            {
                guestContext->VpRegs->Rax = 0;
                guestContext->VpRegs->Rdx = 0;
            }

            vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
            return true;
        }

        //
        // Performance-counter MSRs are answered with zero on read and writes
        // are ignored: the least observable answer, matching a CPU that does
        // not implement these MSRs (WHEA probes rely on this not faulting).
        //
        if (!writeAccess)
        {
            guestContext->VpRegs->Rax = 0;
            guestContext->VpRegs->Rdx = 0;
        }

        vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
        return true;
    }

}
