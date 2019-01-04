// dmp.h : definitions related to Microsoft crash dump header.
//
// (c) Matt Suiche, 2019
// Author: Matt Suiche, msuiche@comae.com
//
#ifndef __CRASHDMP_H__
#define __CRASHDMP_H__
#include "vmm.h"

#define DUMP_SIGNATURE ('EGAP')
#define DUMP_VALID_DUMP ('PMUD')
#define DUMP_VALID_DUMP64 ('46UD')

#define DUMP_TYPE_FULL 1

#define PAGE_SIZE 0x1000
#define PAGE_MASK (~(PAGE_SIZE-1))

#define IMAGE_FILE_MACHINE_I386 0x014c
#define IMAGE_FILE_MACHINE_AMD64 0x8664

typedef struct tdPHYSICAL_MEMORY_RUN32 {
    ULONG BasePage;
    ULONG PageCount;
} PHYSICAL_MEMORY_RUN32, *PPHYSICAL_MEMORY_RUN32;

typedef struct tdPHYSICAL_MEMORY_DESCRIPTOR32 {
    ULONG NumberOfRuns;
    ULONG NumberOfPages;
    PHYSICAL_MEMORY_RUN32 Run[1]; // NumberOfRuns is the total entries.
} PHYSICAL_MEMORY_DESCRIPTOR32, *PPHYSICAL_MEMORY_DESCRIPTOR32;

typedef struct tdPHYSICAL_MEMORY_RUN64 {
    ULONG64 BasePage;
    ULONG64 PageCount;
} PHYSICAL_MEMORY_RUN64, *PPHYSICAL_MEMORY_RUN64;

typedef struct tdPHYSICAL_MEMORY_DESCRIPTOR64 {
    ULONG NumberOfRuns;
    ULONG64 NumberOfPages;
    PHYSICAL_MEMORY_RUN64 Run[1];
} PHYSICAL_MEMORY_DESCRIPTOR64, *PPHYSICAL_MEMORY_DESCRIPTOR64;

typedef struct tdDUMP_HEADER32 {
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG DirectoryTableBase;
    ULONG PfnDataBase;
    ULONG PsLoadedModuleList;
    ULONG PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONG BugCheckParameter1;
    ULONG BugCheckParameter2;
    ULONG BugCheckParameter3;
    ULONG BugCheckParameter4;
    CHAR VersionUser[32];
    CHAR PaeEnabled;
    CHAR KdSecondaryVersion;
    CHAR spare[2];
    ULONG KdDebuggerDataBlock;
    union {
        PHYSICAL_MEMORY_DESCRIPTOR32 PhysicalMemoryBlock;
        UCHAR PhysicalMemoryBlockBuffer[700];
    };
    union {
        CONTEXT Context;
        UCHAR ContextRecord[1200];
    };
    EXCEPTION_RECORD ExceptionRecord;
    CHAR Comment[128];
    UCHAR reserved0[1768];
    ULONG DumpType;
    ULONG MiniDumpFields;
    ULONG SecondaryDataState;
    ULONG ProductType;
    ULONG SuiteMask;
    UCHAR reserved1[4];
    LARGE_INTEGER RequiredDumpSpace;
    UCHAR reserved2[16];
    FILETIME SystemUpTime;
    FILETIME SystemTime;
    UCHAR reserved3[56];
} DUMP_HEADER32, *PDUMP_HEADER32;

typedef struct tdDUMP_HEADER64 {
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG64 DirectoryTableBase;
    ULONG64 PfnDataBase;
    ULONG64 PsLoadedModuleList;
    ULONG64 PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONG64 BugCheckParameter1;
    ULONG64 BugCheckParameter2;
    ULONG64 BugCheckParameter3;
    ULONG64 BugCheckParameter4;
    CHAR VersionUser[32];
    ULONG64 KdDebuggerDataBlock;
    union {
        PHYSICAL_MEMORY_DESCRIPTOR64 PhysicalMemoryBlock;
        UCHAR PhysicalMemoryBlockBuffer[700];
    };
    UCHAR ContextRecord[3000];
    EXCEPTION_RECORD64 ExceptionRecord;
    ULONG DumpType;
    LARGE_INTEGER RequiredDumpSpace;
    FILETIME SystemTime;
    CHAR Comment[0x80]; // May not be present.
    FILETIME SystemUpTime;
    ULONG MiniDumpFields;
    ULONG SecondaryDataState;
    ULONG ProductType;
    ULONG SuiteMask;
    ULONG WriterStatus;
    UCHAR Unused1;
    UCHAR KdSecondaryVersion; // Present only for W2K3 SP1 and better
    UCHAR Unused[2];
    UCHAR _reserved0[4016];
} DUMP_HEADER64, *PDUMP_HEADER64;

BOOL
ReadFileAt(
    FILE *fp,
    ULONG64 offset,
    PVOID *buffer,
    ULONG buffer_size
);

#endif /* __CRASHDMP_H__ */
