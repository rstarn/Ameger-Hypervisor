//
// PeLoader - a self-contained kernel-mode PE loader.
//
// The Mapper driver uses these routines to read a PE image (Hypervisor.sys)
// from disk, map it into NonPagedPool, apply base relocations, resolve its
// imports, and invoke its entry point with a synthetic DRIVER_OBJECT whose
// DriverStart/DriverSize describe the mapped image.
//
#pragma once

#include <ntdef.h>
#include <ntimage.h>
#include <minwindef.h>

//
// Pool tag for every allocation the loader makes ('Thre').  Defined in the
// header so PortableExecutable.cpp and Main.cpp (which frees the mapped image / driver
// object on failure) share one tag.
//
// 'Thre' is the pool tag the kernel's thread subsystem uses for thread
// stacks and TCB allocations (KeCreateThread / PsCreateSystemThread).  It
// appears thousands of times in any live kernel pool dump, so a dump shows
// these allocations blending into ordinary thread allocations.  It is a real
// Microsoft subsystem tag - not a custom marker, and not a tag used exclusively
// by the hypervisor-of-interest's documented techniques.
//
inline constexpr unsigned long PELOADER_POOL_TAG = 'Thre';

// Read the file at ImagePath (a kernel NT path, e.g. \??\C:\hv.sys) into a
// NonPagedPool buffer. On success, sets *OutBuffer / *OutSize; the caller is
// responsible for freeing the buffer (ExFreePoolWithTag).
NTSTATUS PeLoaderReadFile(_In_ PCWSTR ImagePath, _Out_ PVOID* OutBuffer, _Out_ SIZE_T* OutSize);

// Validate the PE image in FileBuffer: DOS header, e_lfanew, PE signature,
// PE32+ optional-header magic, non-zero SizeOfImage, at least one section,
// and a .text section.
NTSTATUS PeLoaderValidate(_In_ PVOID FileBuffer, _In_ SIZE_T FileSize);

// Allocate SizeOfImage bytes from NonPagedPool and copy the headers (first
// SizeOfHeaders bytes) verbatim, then copy each section's raw data and zero
// the padding up to VirtualSize. On success sets *OutMappedBase / *OutImageSize.
NTSTATUS PeLoaderMapImage(_In_ PVOID FileBuffer, _In_ SIZE_T FileSize, _Out_ PVOID* OutMappedBase, _Out_ SIZE_T* OutImageSize);

// Compute delta = MappedBase - OptionalHeader.ImageBase and, when non-zero,
// walk the .reloc section applying the delta to every HIGHLOW (3) or DIR64
// (10) entry.
NTSTATUS PeLoaderApplyRelocations(_In_ PVOID MappedBase);

// Walk the import directory and resolve every named import through
// MmGetSystemRoutineAddress(), writing the resolved kernel address into the
// import address table. By-ordinal imports are rejected rather than guessed.
NTSTATUS PeLoaderResolveImports(_In_ PVOID MappedBase);

// Allocate a DRIVER_OBJECT from NonPagedPool, zero it, set
// DriverStart/DriverSize from the mapped image, then locate the entry point
// at MappedBase + OptionalHeader.AddressOfEntryPoint and invoke it with the
// DRIVER_OBJECT and a minimal service registry path.
NTSTATUS PeLoaderInvokeEntry(_In_ PVOID MappedBase, _Out_ PDRIVER_OBJECT* OutDriverObject);
