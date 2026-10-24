#pragma once

#define NESTED_MODE true

#include <ntifs.h>
#include <intrin.h>
#include <ntdef.h>
#include <minwindef.h>
#include <stddef.h>
#include <ntimage.h>

#include "Utils.h"
#include "Shared.h"

#include "Memory/Physical.h"

#include "SVM/Defines/SVM_Platform.h"
#include "SVM/Defines/SVM_NestedPaging.h"
#include "SVM/Defines/SVM_ControlArea.h"
#include "SVM/Defines/SVM_ProcessorData.h"
#include "SVM/SVM.h"
#include "SVM/Handlers/SVM_VMExit.h"

namespace Global
{
    inline PVOID BlankPage = nullptr;
    inline PVOID PreallocatedPools[32];

    //
    // Per-CPU virtualization state, sized at runtime from the active
    // processor count (this machine: 16 logical CPUs).
    inline PBYTE VirtualizedCpus = nullptr;

    //
    // Size of the MSR permission map in bytes, computed at runtime from
    // CPUID Fn8000_000A on this CPU (AMD Ryzen 7 4800H / Zen 2).
    inline ULONG64 MsrPermissionsMapSize = 0;

    //
    // Dynamic MSR address ranges, computed from CPUID Fn8000_000A:
    //   EAX [51:32] - max offset in the MSR0-1 range (0x00000000 base)
    //   EAX [63:52] - max offset in the MSR2 range (0xC0000000 base)
    inline UINT32 MsrRange01Max = 0;
    inline UINT32 MsrRange2Max = 0;

    namespace Offsets
    {
        //
        // EPROCESS layout, resolved at boot from the running kernel image.
        // Defaults are zeroed so that any consumer that somehow runs before
        // GetOffsets() will fault immediately rather than silently trusting a
        // build-specific offset. Entry() refuses to continue if GetOffsets()
        // fails, so these are never actually relied upon on a supported system.
        inline ULONG64 ActiveProcessLinks = 0;
        inline ULONG64 UniqueProcessId = 0;
        inline ULONG64 DirectoryTableBase = 0;

        //
        // Runtime-validated flag: true once GetOffsets() has successfully
        // resolved all EPROCESS layout offsets dynamically.
        inline bool Resolved = false;
    }

    //
    // Highest valid user-mode address for this OS build, read at boot from
    // the kernel's MmHighestUserAddress. Win11 24H2 uses a 64-bit user space
    // split, so the user/kernel boundary is MmHighestUserAddress (≈
    // 0x7FFFFFFFFFFF), not the old 48-bit 0x7FFFFFFEFFFF. Both
    // Utils::ValidUsermodeAddress and SVM::IsInUserland key off this.
    inline ULONG64 HighestUserAddress = 0;

    //
    // Dynamically resolved at boot via MmGetSystemRoutineAddress (with an
    // export-table-parsing fallback). These replace the old hardcoded -6
    // (48-byte) offset into the OBJECT_HEADER for the PointerCount field,
    // which varied silently between Windows builds. When the function
    // pointers are available they are preferred; otherwise the
    // ReferenceCountOffset (discovered by pattern-scanning the kernel image)
    // is used as a fallback.
    inline PVOID pObfReferenceObject = nullptr;
    inline PVOID pObfDereferenceObject = nullptr;
    inline ULONG32 ReferenceCountOffset = 0;
    inline bool UseObFunctions = false;
}