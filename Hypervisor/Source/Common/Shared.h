#pragma once

#include <stddef.h>

namespace Shared
{
    constexpr ULONG64 MAGIC = 0xfeed3;
    constexpr ULONG64 COMM_CHECK = 0xdead;

    constexpr ULONG64 MAX_RW_SIZE = 0x10000;

    enum CommandId
    {
        Invalid,
        CheckPresence,
        GetProcess,
        GetDirectoryBase,
        CopyProcessMemory,
        ProtectSelf,
        FlushNpt,
        ProtectRange,
        GetDriverInfo,
    };

    enum ErrorCodes
    {
        Success,
        ControlBlockReadFail,
        MemoryCopyTooLarge,
        MemoryCopyFailSource,
        MemoryCopyFailTarget,
        InvalidProcess,
    };

    typedef struct _COPY_MEMORY_DATA
    {
        ULONG32 SourceProcessId;        // 0x00
        ULONG32 DestinationProcessId;   // 0x04
        ULONG64 SourceAddress;          // 0x08
        ULONG64 DestinationAddress;     // 0x10
        SIZE_T NumberOfBytes;           // 0x18
    } COPY_MEMORY_DATA;

    static_assert(sizeof(COPY_MEMORY_DATA) == 32, "COPY_MEMORY_DATA ABI mismatch");
    static_assert(offsetof(COPY_MEMORY_DATA, SourceProcessId) == 0x00, "COPY_MEMORY_DATA.SourceProcessId ABI mismatch");
    static_assert(offsetof(COPY_MEMORY_DATA, DestinationProcessId) == 0x04, "COPY_MEMORY_DATA.DestinationProcessId ABI mismatch");
    static_assert(offsetof(COPY_MEMORY_DATA, SourceAddress) == 0x08, "COPY_MEMORY_DATA.SourceAddress ABI mismatch");
    static_assert(offsetof(COPY_MEMORY_DATA, DestinationAddress) == 0x10, "COPY_MEMORY_DATA.DestinationAddress ABI mismatch");
    static_assert(offsetof(COPY_MEMORY_DATA, NumberOfBytes) == 0x18, "COPY_MEMORY_DATA.NumberOfBytes ABI mismatch");

    //
    // GetDriverInfo (command 0x08): returns the driver's image base/size and its
    // resolved .text section range.  Written to the caller's user buffer (R8).
    //
    typedef struct _DRIVER_INFO
    {
        ULONG64 DriverBase;    // 0x00
        SIZE_T  DriverSize;    // 0x08
        ULONG64 TextBase;      // 0x10
        SIZE_T  TextSize;      // 0x18
    } DRIVER_INFO;

    static_assert(sizeof(DRIVER_INFO) == 32, "DRIVER_INFO ABI mismatch");
    static_assert(offsetof(DRIVER_INFO, DriverBase) == 0x00, "DRIVER_INFO.DriverBase ABI mismatch");
    static_assert(offsetof(DRIVER_INFO, DriverSize) == 0x08, "DRIVER_INFO.DriverSize ABI mismatch");
    static_assert(offsetof(DRIVER_INFO, TextBase) == 0x10, "DRIVER_INFO.TextBase ABI mismatch");
    static_assert(offsetof(DRIVER_INFO, TextSize) == 0x18, "DRIVER_INFO.TextSize ABI mismatch");
}