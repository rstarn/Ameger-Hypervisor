#pragma once

#include "Defines/ProcessorData.h"

//
// CPUID / MSR stealth hardening.  Everything here is gated by the
// HYPERVISOR_STEALTH flag (default on); when it is off these become no-ops
// and the original handler behaviour is preserved.
//
// There is deliberately no TSC-offset compensation: a per-CPU VMCB TscOffset
// made the guest's TSC differ between CPUs and step backwards when a thread
// migrated, which violates the invariant-TSC assumption Windows (and every
// user-mode timing loop) relies on.
//
namespace Stealth
{
    // Arms the per-CPU CPUID spoofing table (leaf 0x1, 0x80000001, and the
    // 0x40000000-0x4FFFFFFF hypervisor range).
    void ConfigureCpuidSpoofing();

    // Sets the MSR permission-map bits for the performance-counter MSRs on top
    // of what BuildPermissionMap already set for EFER / VM_CR / VM_HSAVE_PA.
    void ConfigureMsrIntercepts(const SVM::PSHARED_VIRTUAL_PROCESSOR_DATA sharedData);

    // Returns true when the CPUID leaf is in the hypervisor range
    // (0x40000000-0x4FFFFFFF): the handler writes zero to all four result
    // registers and advances NRip.  Leaves 0x1 and 0x80000001 are already
    // masked by the existing HandleCPUID, so this returns false for them and
    // the existing handler keeps doing its job (no change to non-stealth
    // leaves).
    bool HandleCpuidSpoof(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext);

    // Returns true when the accessed MSR is a stealth MSR (VM_CR,
    // VM_HSAVE_PA, performance counters) and the handler wrote a clean value
    // and advanced NRip; false defers to the existing HandleMSRAccess.  EFER
    // is deliberately delegated: HandleMSRAccess owns the single validated
    // EFER implementation.
    bool HandleMsrAccess(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext);
}
