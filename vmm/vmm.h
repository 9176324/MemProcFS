// vmm.h : definitions related to virtual memory management support.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMM_H__
#define __VMM_H__
#include <windows.h>
#include <stdio.h>

typedef unsigned __int64                QWORD, *PQWORD;

#define MEM_IO_SCATTER_HEADER_VERSION   2

typedef struct tdMEM_IO_SCATTER_HEADER {
    ULONG64 qwA;            // base address (DWORD boundry).
    DWORD cbMax;            // bytes to read (DWORD boundry, max 0x1000); pbResult must have room for this.
    DWORD cb;               // bytes read into result buffer.
    PBYTE pb;               // ptr to 0x1000 sized buffer to receive read bytes.
    PVOID pvReserved1;      // reserved for use by caller.
    PVOID pvReserved2;      // reserved for use by caller.
    WORD version;           // version of struct 
    WORD Future1;           // reserved for future use.
    DWORD Future2;          // reserved for future use.
    ULONG64 qwDeviceA;      // device-physical address (used by device layer).
    struct {
        PVOID pvReserved1;
        PVOID pvReserved2;
        BYTE pbReserved[32];
    } sReserved;            // reserved for future use.
} MEM_IO_SCATTER_HEADER, *PMEM_IO_SCATTER_HEADER, **PPMEM_IO_SCATTER_HEADER;

// ----------------------------------------------------------------------------
// VMM configuration constants and struct definitions below:
// ----------------------------------------------------------------------------

#define VMM_STATUS_SUCCESS                      ((NTSTATUS)0x00000000L)
#define VMM_STATUS_UNSUCCESSFUL                 ((NTSTATUS)0xC0000001L)
#define VMM_STATUS_END_OF_FILE                  ((NTSTATUS)0xC0000011L)
#define VMM_STATUS_FILE_INVALID                 ((NTSTATUS)0xC0000098L)
#define VMM_STATUS_FILE_SYSTEM_LIMITATION       ((NTSTATUS)0xC0000427L)

#define VMM_PROCESSTABLE_ENTRIES_MAX            0x4000
#define VMM_PROCESS_OS_ALLOC_PTR_MAX            0x4    // max number of operating system specific pointers that must be free'd
#define VMM_MEMMAP_ENTRIES_MAX                  0x4000

#define VMM_MEMMAP_FLAG_PAGE_W                  0x0000000000000002
#define VMM_MEMMAP_FLAG_PAGE_NS                 0x0000000000000004
#define VMM_MEMMAP_FLAG_PAGE_NX                 0x8000000000000000
#define VMM_MEMMAP_FLAG_PAGE_MASK               0x8000000000000006

#define VMM_CACHE_TABLESIZE                     0x4011  // (not even # to prevent clogging at specific table 'hash' buckets)
#define VMM_CACHE_TLB_ENTRIES                   0x4000  // -> 64MB of cached data
#define VMM_CACHE_PHYS_ENTRIES                  0x4000  // -> 64MB of cached data

#define VMM_FLAG_NOCACHE                        0x0001  // do not use the data cache (force reading from memory acquisition device)
#define VMM_FLAG_ZEROPAD_ON_FAIL                0x0002  // zero pad failed physical memory reads and report success if read within range of physical memory.
#define VMM_FLAG_PROCESS_SHOW_TERMINATED        0x0004  // show terminated processes in the process list (if they can be found).

#define VMM_VERSION_MAJOR                       1
#define VMM_VERSION_MINOR                       2
#define VMM_VERSION_REVISION                    1

static const LPSTR VMM_MEMORYMODEL_TOSTRING[4] = { "N/A", "X86", "X86PAE", "X64" };

typedef enum tdVMM_MEMORYMODEL_TP {
    VMM_MEMORYMODEL_NA      = 0,
    VMM_MEMORYMODEL_X86     = 1,
    VMM_MEMORYMODEL_X86PAE  = 2,
    VMM_MEMORYMODEL_X64     = 3
} VMM_MEMORYMODEL_TP;

typedef enum tdVMM_SYSTEM_TP {
    VMM_SYSTEM_UNKNOWN_X64  = 1,
    VMM_SYSTEM_WINDOWS_X64  = 2,
    VMM_SYSTEM_UNKNOWN_X86  = 3,
    VMM_SYSTEM_WINDOWS_X86  = 4
} VMM_SYSTEM_TP;

typedef struct tdVMM_MEMMAP_ENTRY {
    QWORD AddrBase;
    QWORD cPages;
    QWORD fPage;
    BOOL  fWoW64;
    CHAR  szTag[32];
} VMM_MEMMAP_ENTRY, *PVMM_MEMMAP_ENTRY;

typedef struct tdVMM_MODULEMAP_ENTRY {
    QWORD BaseAddress;
    QWORD EntryPoint;
    DWORD SizeOfImage;
    BOOL  fWoW64;
    CHAR  szName[32];
    // # of entries in EAT / IAT (lazy loaded due to performance reasons)
    BOOL  fLoadedEAT;
    DWORD cbDisplayBufferEAT;
    BOOL  fLoadedIAT;
    DWORD cbDisplayBufferIAT;
    DWORD cbDisplayBufferSections;
} VMM_MODULEMAP_ENTRY, *PVMM_MODULEMAP_ENTRY;

typedef struct tdVMM_PROCESS {
    DWORD dwPID;
    DWORD dwState;          // state of process, 0 = running
    QWORD paDTB;
    QWORD paDTB_UserOpt;
    CHAR szName[16];
    BOOL _i_fMigrated;
    BOOL fUserOnly;
    BOOL fSpiderPageTableDone;
    BOOL fFileCacheDisabled;
    // memmap related pointers (free must be called separately)
    QWORD cMemMap;
    PVMM_MEMMAP_ENTRY pMemMap;
    PBYTE pbMemMapDisplayCache;
    QWORD cbMemMapDisplayCache;
    // module map (free must be called separately)
    QWORD cModuleMap;
    PVMM_MODULEMAP_ENTRY pModuleMap;
    union {
        struct {
            PVOID pvReserved[VMM_PROCESS_OS_ALLOC_PTR_MAX]; // os-specific buffer to be allocated if needed (free'd by VmmClose)
        } unk;
        struct {
            PBYTE pbLdrModulesDisplayCache;
            PVOID pbReserved[VMM_PROCESS_OS_ALLOC_PTR_MAX - 1];
            DWORD cbLdrModulesDisplayCache;
            QWORD vaEPROCESS;
            QWORD vaPEB;
            DWORD vaPEB32;                          // WoW64 only
            QWORD vaENTRY;
            BOOL fWow64;
        } win;
    } os;
} VMM_PROCESS, *PVMM_PROCESS;

typedef struct tdVMM_PROCESS_TABLE {
    SIZE_T c;
    WORD iFLink;
    WORD iFLinkM[VMM_PROCESSTABLE_ENTRIES_MAX];
    PVMM_PROCESS M[VMM_PROCESSTABLE_ENTRIES_MAX];
    struct tdVMM_PROCESS_TABLE *ptNew;
} VMM_PROCESS_TABLE, *PVMM_PROCESS_TABLE;

#define VMM_CACHE_ENTRY_MAGIC 0x29d50298c4921034

typedef struct tdVMM_CACHE_ENTRY {
    QWORD qwMAGIC;
    struct tdVMM_CACHE_ENTRY *FLink;
    struct tdVMM_CACHE_ENTRY *BLink;
    struct tdVMM_CACHE_ENTRY *AgeFLink;
    struct tdVMM_CACHE_ENTRY *AgeBLink;
    QWORD tm;
    MEM_IO_SCATTER_HEADER h;
    BYTE pb[0x1000];
} VMM_CACHE_ENTRY, *PVMM_CACHE_ENTRY, **PPVMM_CACHE_ENTRY;

typedef struct tdVMM_CACHE_TABLE {
    PVMM_CACHE_ENTRY M[VMM_CACHE_TABLESIZE];
    PVMM_CACHE_ENTRY AgeFLink;
    PVMM_CACHE_ENTRY AgeBLink;
    PVMM_CACHE_ENTRY S;
} VMM_CACHE_TABLE, *PVMM_CACHE_TABLE;

typedef struct tdVMM_VIRT2PHYS_INFORMATION {
    VMM_MEMORYMODEL_TP tpMemoryModel;
    QWORD va;
    QWORD pas[5];   // physical addresses of pagetable[PML]/page[0]
    QWORD PTEs[5];  // PTEs[PML]
    WORD  iPTEs[5]; // Index of PTE in page table
} VMM_VIRT2PHYS_INFORMATION, *PVMM_VIRT2PHYS_INFORMATION;

typedef struct tdVMM_MEMORYMODEL_FUNCTIONS {
    VOID(*pfnInitialize)();
    VOID(*pfnClose)();
    BOOL(*pfnVirt2Phys)(_In_ QWORD paDTB, _In_ BOOL fUserOnly, _In_ BYTE iPML, _In_ QWORD va, _Out_ PQWORD ppa);
    VOID(*pfnVirt2PhysGetInformation)(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo);
    VOID(*pfnMapInitialize)(_In_ PVMM_PROCESS pProcess);
    VOID(*pfnMapTag)(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_opt_ BOOL fWoW64);
    PVMM_MEMMAP_ENTRY(*pfnMapGetEntry)(_In_ PVMM_PROCESS pProcess, _In_ QWORD va);
    VOID(*pfnMapDisplayBufferGenerate)(_In_ PVMM_PROCESS pProcess);
    VOID(*pfnTlbSpider)(_In_ QWORD paDTB, _In_ BOOL fUserOnly);
    BOOL(*pfnTlbPageTableVerify)(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq);
} VMM_MEMORYMODEL_FUNCTIONS;

// ----------------------------------------------------------------------------
// VMM general constants and struct definitions below: 
// ----------------------------------------------------------------------------

typedef struct tdVmmConfig {
    CHAR szMountPoint[1];
    CHAR szDevTpOrFileName[MAX_PATH];
    CHAR szPythonPath[MAX_PATH];
    QWORD paCR3;
    QWORD paAddrMax;
    // flags below
    BOOL fCommandIdentify;
    BOOL fVerboseDll;
    BOOL fVerbose;
    BOOL fVerboseExtra;
    BOOL fVerboseExtraTlp;
} VMMCONFIG, *PVMMCONFIG;

typedef enum tdVMM_DEVICE_TYPE {
    VMM_DEVICE_NA,
    VMM_DEVICE_FILE,
    VMM_DEVICE_PCILEECH_DLL,
} VMM_DEVICE_TYPE;

typedef struct tdVmmDeviceConfig {
    HANDLE hDevice;
    QWORD paAddrMaxNative;
    QWORD qwMaxSizeMemIo;
    VMM_DEVICE_TYPE tp;
    VOID(*pfnReadScatterMEM)(_Inout_ PPMEM_IO_SCATTER_HEADER ppDMAs, _In_ DWORD cpDMAs, _Out_opt_ PDWORD pcpDMAsRead);
    BOOL(*pfnWriteMEM)(_In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb);
    VOID(*pfnClose)();
    BOOL(*pfnGetOption)(_In_ QWORD fOption, _Out_ PQWORD pqwValue);
    BOOL(*pfnSetOption)(_In_ QWORD fOption, _In_ QWORD qwValue);
} VMMDEVICE_CONFIG, *PVMMDEVICE_CONFIG;

typedef struct tdVMM_STATISTICS {
    QWORD cPhysCacheHit;
    QWORD cPhysReadSuccess;
    QWORD cPhysReadFail;
    QWORD cPhysWrite;
    QWORD cTlbCacheHit;
    QWORD cTlbReadSuccess;
    QWORD cTlbReadFail;
    QWORD cRefreshPhys;
    QWORD cRefreshTlb;
    QWORD cRefreshProcessPartial;
    QWORD cRefreshProcessFull;
} VMM_STATISTICS, *PVMM_STATISTICS;

typedef struct tdVMM_KERNELINFO {
    QWORD paDTB;
    QWORD vaBase;
    QWORD cbSize;
    // optional non-required values below
    QWORD vaEntry;
    QWORD vaPsLoadedModuleList;
    QWORD vaKDBG;
} VMM_KERNELINFO;

typedef struct tdVMM_CONTEXT {
    CRITICAL_SECTION MasterLock;
    PVMM_PROCESS_TABLE ptPROC;
    PVMM_CACHE_TABLE ptTLB;
    PVMM_CACHE_TABLE ptPHYS;
    BOOL fReadOnly;
    VMM_MEMORYMODEL_FUNCTIONS fnMemoryModel;
    VMM_MEMORYMODEL_TP tpMemoryModel;
    BOOL f32;
    VMM_SYSTEM_TP tpSystem;
    DWORD flags;    // VMM_FLAG_*
    struct {
        BOOL fEnabled;
        HANDLE hThread;
        DWORD cMs_TickPeriod;
        DWORD cTick_Phys;
        DWORD cTick_TLB;
        DWORD cTick_ProcPartial;
        DWORD cTick_ProcTotal;
    } ThreadProcCache;
    VMM_STATISTICS stat;
    VMM_KERNELINFO kernel;
    PVOID pVmmVfsModuleList;
} VMM_CONTEXT, *PVMM_CONTEXT;

typedef struct tdVMM_MAIN_CONTEXT {
    VMMCONFIG cfg;
    VMMDEVICE_CONFIG dev;
    PVOID pvStatistics;
} VMM_MAIN_CONTEXT, *PVMM_MAIN_CONTEXT;

// ----------------------------------------------------------------------------
// VMM global variables below:
// ----------------------------------------------------------------------------

PVMM_CONTEXT ctxVmm;
PVMM_MAIN_CONTEXT ctxMain;

#define vmmprintf(format, ...)     { if(ctxMain->cfg.fVerboseDll)       { printf(format, ##__VA_ARGS__); } }
#define vmmprintfv(format, ...)    { if(ctxMain->cfg.fVerbose)          { printf(format, ##__VA_ARGS__); } }
#define vmmprintfvv(format, ...)   { if(ctxMain->cfg.fVerboseExtra)     { printf(format, ##__VA_ARGS__); } }
#define vmmprintfvvv(format, ...)  { if(ctxMain->cfg.fVerboseExtraTlp)  { printf(format, ##__VA_ARGS__); } }

// ----------------------------------------------------------------------------
// VMM reserved for memory model use only functions below:
// ----------------------------------------------------------------------------
PMEM_IO_SCATTER_HEADER VmmCacheGet(_In_ PVMM_CACHE_TABLE t, _In_ QWORD qwA);
VOID VmmCachePut(_Inout_ PVMM_CACHE_TABLE t, _In_ PVMM_CACHE_ENTRY e);
PVMM_CACHE_ENTRY VmmCacheReserve(_Inout_ PVMM_CACHE_TABLE t);

// ----------------------------------------------------------------------------
// VMM function definitions below:
// ----------------------------------------------------------------------------

/*
* Acquire the VMM master lock. Required if interoperating with the VMM from a
* function that has not already acquired the lock. Lock must be relased in a
* fairly short amount of time in order for the VMM to continue working.
* !!! MUST NEVER BE ACQUIRED FOR LENGTHY AMOUNT OF TIMES !!!
*/
VOID VmmLockAcquire();

/*
* Release VMM master lock that has previously been acquired by VmmLockAcquire.
*/
VOID VmmLockRelease();

/*
* Write a virtually contigious arbitrary amount of memory.
* -- pProcess
* -- qwVA
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
BOOL VmmWrite(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Write physical memory and clear any VMM caches that may contain data.
* -- pa
* -- pb
* -- cb
* -- return
*/
BOOL VmmWritePhysical(_In_ QWORD pa, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Read a virtually contigious arbitrary amount of memory containing cch number of
* unicode characters and convert them into ansi characters. Characters > 0xff are
* converted into '?'. The result is guaranteed to be zero-terminated.
* -- pProcess
* -- qwVA
* -- sz
* -- cch
* -- return
*/
_Success_(return)
BOOL VmmReadString_Unicode2Ansi(_In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_writes_(cch) LPSTR sz, _In_ DWORD cch);

/*
* Read a contigious arbitrary amount of memory, virtual or physical.
* Virtual memory is read if a process is specified in pProcess parameter.
* Physical memory is read if NULL is specified in pProcess parameter.
* -- pProcess
* -- qwVA = NULL=='physical memory read', PTR=='virtual memory read'
* -- pb
* -- cb
* -- return
*/
BOOL VmmRead(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Read a contigious arbitrary amount of memory, physical or virtual, and report
* the number of bytes read in pcbRead.
* Virtual memory is read if a process is specified in pProcess.
* Physical memory is read if NULL is specified in pProcess.
* -- pProcess = NULL=='physical memory read', PTR=='virtual memory read'
* -- qwA
* -- pb
* -- cb
* -- pcbRead
* -- flags = flags as in VMM_FLAG_*
*/
VOID VmmReadEx(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ QWORD flags);

/*
* Read a single 4096-byte page of memory, virtual or physical.
* Virtual memory is read if a process is specified in pProcess.
* Physical memory is read if NULL is specified in pProcess.
* -- pProcess = NULL=='physical memory read', PTR=='virtual memory read'
* -- qwA
* -- pbPage
* -- return
*/
BOOL VmmReadPage(_In_opt_ PVMM_PROCESS pProcess, _In_ QWORD qwA, _Inout_bytecount_(4096) PBYTE pbPage);

/*
* Scatter read virtual memory. Non contiguous 4096-byte pages.
* -- pProcess
* -- ppMEMsVirt
* -- cpMEMsVirt
* -- flags = flags as in VMM_FLAG_*, [VMM_FLAG_NOCACHE for supression of data (not tlb) caching]
*/
VOID VmmReadScatterVirtual(_In_ PVMM_PROCESS pProcess, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsVirt, _In_ DWORD cpMEMsVirt, _In_ QWORD flags);

/*
* Scatter read physical memory. Non contiguous 4096-byte pages.
* -- ppMEMsPhys
* -- cpMEMsPhys
* -- flags = flags as in VMM_FLAG_*, [VMM_FLAG_NOCACHE for supression of caching]
*/
VOID VmmReadScatterPhysical(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMsPhys, _In_ DWORD cpMEMsPhys, _In_ QWORD flags);

/*
* Read a single 4096-byte page of physical memory.
* -- qwPA
* -- pbPage
* -- return
*/
BOOL VmmReadPhysicalPage(_In_ QWORD qwPA, _Inout_bytecount_(4096) PBYTE pbPage);

/*
* Retrieve a page table (0x1000 bytes) via the TLB cache.
* -- pa
* -- fCacheOnly = if set do not make a request to underlying device if not in cache.
* -- return
*/
PBYTE VmmTlbGetPageTable(_In_ QWORD pa, _In_ BOOL fCacheOnly);

/*
* Translate a virtual address to a physical address by walking the page tables.
* -- paDTB
* -- fUserOnly
* -- va
* -- ppa
* -- return
*/
_Success_(return)
inline BOOL VmmVirt2PhysEx(_In_ QWORD paDTB, _In_ BOOL fUserOnly, _In_ QWORD va, _Out_ PQWORD ppa)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnVirt2Phys(paDTB, fUserOnly, -1, va, ppa);
}

/*
* Translate a virtual address to a physical address by walking the page tables.
* -- pProcess
* -- va
* -- ppa
* -- return
*/
_Success_(return)
inline BOOL VmmVirt2Phys(_In_ PVMM_PROCESS pProcess, _In_ QWORD va, _Out_ PQWORD ppa)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnVirt2Phys(pProcess->paDTB, pProcess->fUserOnly, -1, va, ppa);
}

/*
* Spider the TLB (page table cache) to load all page table pages into the cache.
* This is done to speed up various subsequent virtual memory accesses.
* NB! pages may fall out of the cache if it's in heavy use or doe to timing.
* -- paDTB      = physical adderss of the Directory Table Base (DTB) to spider.
                  (aka. Page Mapping Level 4 table in x64).
* -- fUserOnly  = only spider user-mode (ring3) pages, no kernel pages.
*/
inline VOID VmmTlbSpider(_In_ QWORD paDTB, _In_ BOOL fUserOnly)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    ctxVmm->fnMemoryModel.pfnTlbSpider(paDTB, fUserOnly);
}

/*
* Try verify that a supplied page table in pb is valid by analyzing it.
* -- pb = 0x1000 bytes containing the page table page.
* -- pa = physical address if the page table page.
* -- fSelfRefReq = is a self referential entry required to be in the map? (PML4 for Windows).
*/
inline BOOL VmmTlbPageTableVerify(_Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return FALSE; }
    return ctxVmm->fnMemoryModel.pfnTlbPageTableVerify(pb, pa, fSelfRefReq);
}

/*
* Retrieve information of the virtual2physical address translation for the
* supplied process. The Virtual address must be supplied in pVirt2PhysInfo upon
* entry.
* -- pProcess
* -- pVirt2PhysInfo
*/
inline VOID VmmVirt2PhysGetInformation(_Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_VIRT2PHYS_INFORMATION pVirt2PhysInfo)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    ctxVmm->fnMemoryModel.pfnVirt2PhysGetInformation(pProcess, pVirt2PhysInfo);
}

/*
* Initialize the memory map for a specific process. This may take some time
* especially for kernel/system processes.
* -- pProcess
*/
inline VOID VmmMapInitialize(_In_ PVMM_PROCESS pProcess)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    ctxVmm->fnMemoryModel.pfnMapInitialize(pProcess);
}

/*
* Map a tag into the sorted memory map in O(log2) operations. Supply only one
* of szTag or wszTag. Tags are usually module/dll name.
* -- pProcess
* -- vaBase
* -- vaLimit = limit == vaBase + size (== top address in range +1)
* -- szTag
* -- wszTag
* -- fWoW64
*/
inline VOID VmmMapTag(_In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag, _In_opt_ BOOL fWoW64)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    ctxVmm->fnMemoryModel.pfnMapTag(pProcess, vaBase, vaLimit, szTag, wszTag, fWoW64);
}

/*
* Retrieve a memory map entry info given a specific address.
* -- pProcess
* -- qwVA
* -- return = the memory map entry or NULL if not found.
*/
inline PVMM_MEMMAP_ENTRY VmmMapGetEntry(_In_ PVMM_PROCESS pProcess, _In_ QWORD va)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return NULL; }
    return ctxVmm->fnMemoryModel.pfnMapGetEntry(pProcess, va);
}

/*
* Generate the human-readable text byte-buffer representing an already existing
* memory map in the process. This memory map must have been initialized with a
* separate call to VmmMapInitialize.
* -- pProcess
*/
inline VOID VmmMapDisplayBufferGenerate(_In_ PVMM_PROCESS pProcess)
{
    if(ctxVmm->tpMemoryModel == VMM_MEMORYMODEL_NA) { return; }
    ctxVmm->fnMemoryModel.pfnMapDisplayBufferGenerate(pProcess);
}

/*
* Create or re-create the entire process table. This will clean the complete and
* all existing processes will be cleared.
* -- return
*/
BOOL VmmProcessCreateTable();

/*
* Retrieve an existing process given a process id (PID).
* -- dwPID
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGet(_In_ DWORD dwPID);

/*
* Create a new process item. New process items are created in a separate data
* structure and won't become visible to the "Process" functions until after the
* VmmProcessCreateFinish have been called.
*/
PVMM_PROCESS VmmProcessCreateEntry(_In_ DWORD dwPID, _In_ DWORD dwState, _In_ QWORD paDTB, _In_ QWORD paDTB_UserOpt, _In_ CHAR szName[16], _In_ BOOL fUserOnly, _In_ BOOL fSpiderPageTableDone);

/*
* Activate the pending, not yet active, processes added by VmmProcessCreateEntry.
* This will also clear any previous processes.
*/
VOID VmmProcessCreateFinish();

/*
* List the PIDs and put them into the supplied table.
* -- pPIDs = user allocated DWORD array to receive result, or NULL.
* -- pcPIDs = ptr to number of DWORDs in pPIDs on entry - number of PIDs in system on exit.
*/
VOID VmmProcessListPIDs(_Out_opt_ PDWORD pPIDs, _Inout_ PSIZE_T pcPIDs);

/*
* Clear the specified cache from all entries.
* -- fTLB
* -- fPHYS
*/
VOID VmmCacheClear( _In_ BOOL fTLB, _In_ BOOL fPHYS);

/*
* Invalidate cache entries belonging to a specific physical address.
* -- pa
*/
VOID VmmCacheInvalidate( _In_ QWORD pa);

/*
* Initialize the memory model specified and discard any previous memory models
* that may be in action.
* -- tp
*/
VOID VmmInitializeMemoryModel(_In_ VMM_MEMORYMODEL_TP tp);

/*
* Initialize a new VMM context. This must always be done before calling any
* other VMM functions. An alternative way to do this is to call the function:
* VmmProcInitialize.
* -- return
*/
BOOL VmmInitialize();

/*
* Close and clean up the VMM context inside the PCILeech context, if existing.
*/
VOID VmmClose();

#endif /* __VMM_H__ */
