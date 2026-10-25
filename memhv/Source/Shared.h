#pragma once

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
        ULONG64 SourceDirectoryBase;
        ULONG64 SourceAddress;
        ULONG64 DestinationDirectoryBase;
        ULONG64 DestinationAddress;
        SIZE_T NumberOfBytes;
    } COPY_MEMORY_DATA;
}