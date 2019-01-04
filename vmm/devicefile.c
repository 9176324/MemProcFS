// devicefile.c : implementation related to file backed memory acquisition device.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "dmp.h"
#include "devicefile.h"
#include "util.h"
#include "vmm.h"

BOOL
InitializeFileContextByType(
    PDEVICE_CONTEXT_FILE ctxFile
) {

    PVOID Buffer = (PDEVICE_CONTEXT_FILE)LocalAlloc(LMEM_ZEROINIT, sizeof(DUMP_HEADER64));
    PDUMP_HEADER64 pDumpHeader64 = (PDUMP_HEADER64)Buffer;
    PDUMP_HEADER32 pDumpHeader = (PDUMP_HEADER32)Buffer;

    BOOL Status = FALSE;

    if (!ReadFileAt(ctxFile->pFile, 0, Buffer, sizeof(DUMP_HEADER64))) {
        vmmprintfv(__FUNCTION__ ": Failed opening file header.\n");
        goto fail;
    }

    if (pDumpHeader->Signature != DUMP_SIGNATURE) {
        ctxFile->Type = FileTypeRaw;
    }
    else {
        if (pDumpHeader->ValidDump == DUMP_VALID_DUMP) {
            ULONG NumberOfRuns = pDumpHeader->PhysicalMemoryBlock.NumberOfRuns;
            ULONG NumberOfPages = pDumpHeader->PhysicalMemoryBlock.NumberOfPages;
            ctxFile->Type = FileTypeDmp;

            vmmprintfvv(__FUNCTION__ ": NumberOfRuns=%d NumberOfPages=0x%x sizeof(PDUMP_HEADER64)=0x%I64X\n",
                NumberOfRuns,
                NumberOfPages,
                sizeof(DUMP_HEADER32));

            ULONG cbMemDescriptors = NumberOfRuns * sizeof(PHYSICAL_MEMORY_RUN64) + sizeof(PPHYSICAL_MEMORY_DESCRIPTOR64);
            ctxFile->MemoryDescriptors = (PPHYSICAL_MEMORY_DESCRIPTOR64)LocalAlloc(LMEM_ZEROINIT, cbMemDescriptors);
            if (!ctxFile->MemoryDescriptors) { return FALSE; }

            ctxFile->MemoryDescriptors->NumberOfPages = pDumpHeader->PhysicalMemoryBlock.NumberOfPages;
            ctxFile->MemoryDescriptors->NumberOfRuns = NumberOfRuns;
            for (ULONG i = 0; i < NumberOfRuns; i++) {
                vmmprintfvv(__FUNCTION__ ": [%d] 0x%I64X-0x%I64X\n",
                    i,
                    (ULONG64)(pDumpHeader->PhysicalMemoryBlock.Run[i].BasePage * PAGE_SIZE),
                    (ULONG64)(pDumpHeader->PhysicalMemoryBlock.Run[i].PageCount * PAGE_SIZE));

                ctxFile->MemoryDescriptors->Run[i].BasePage = pDumpHeader->PhysicalMemoryBlock.Run[i].BasePage;
                ctxFile->MemoryDescriptors->Run[i].PageCount = pDumpHeader->PhysicalMemoryBlock.Run[i].PageCount;
            }

            vmmprintfvv(__FUNCTION__ ": DirectoryTableBase: 0x%X\n", pDumpHeader->DirectoryTableBase);
            vmmprintfvv(__FUNCTION__ ": KdDebuggerDataBlock: 0x%X\n", pDumpHeader->KdDebuggerDataBlock);
            vmmprintfvv(__FUNCTION__ ": PsActiveProcessHead: 0x%X\n", pDumpHeader->PsActiveProcessHead);
            vmmprintfvv(__FUNCTION__ ": PsLoadedModuleList: 0x%X\n", pDumpHeader->PsLoadedModuleList);

            ctxMain->cfg.paCR3 = pDumpHeader->DirectoryTableBase & PAGE_MASK;
            ctxVmm->kernel.paDTB = pDumpHeader->DirectoryTableBase & PAGE_MASK;
            ctxVmm->kernel.vaPsLoadedModuleList = pDumpHeader->PsLoadedModuleList;
            ctxVmm->kernel.vaKDBG = pDumpHeader->KdDebuggerDataBlock;
        }
        else if (pDumpHeader->ValidDump == DUMP_VALID_DUMP64) {
            ULONG NumberOfRuns = pDumpHeader64->PhysicalMemoryBlock.NumberOfRuns;
            ULONG64 NumberOfPages = pDumpHeader64->PhysicalMemoryBlock.NumberOfPages;
            ctxFile->Type = FileTypeDmp64;

            vmmprintfvv(__FUNCTION__ ": NumberOfRuns=%d NumberOfPages=0x%I64X sizeof(PDUMP_HEADER64)=0x%I64X\n",
                NumberOfRuns,
                NumberOfPages,
                sizeof(DUMP_HEADER64));

            ULONG cbMemDescriptors = NumberOfRuns * sizeof(PHYSICAL_MEMORY_RUN64) + sizeof(PPHYSICAL_MEMORY_DESCRIPTOR64);
            ctxFile->MemoryDescriptors = (PPHYSICAL_MEMORY_DESCRIPTOR64)LocalAlloc(LMEM_ZEROINIT, cbMemDescriptors);
            if (!ctxFile->MemoryDescriptors) { return FALSE; }

            ctxFile->MemoryDescriptors->NumberOfPages = pDumpHeader64->PhysicalMemoryBlock.NumberOfPages;
            ctxFile->MemoryDescriptors->NumberOfRuns = NumberOfRuns;
            for (ULONG i = 0; i < NumberOfRuns; i++) {
                vmmprintfvv(__FUNCTION__ ": [%d] 0x%I64X-0x%I64X\n",
                    i,
                    pDumpHeader64->PhysicalMemoryBlock.Run[i].BasePage * PAGE_SIZE,
                    pDumpHeader64->PhysicalMemoryBlock.Run[i].PageCount * PAGE_SIZE);

                ctxFile->MemoryDescriptors->Run[i].BasePage = pDumpHeader64->PhysicalMemoryBlock.Run[i].BasePage;
                ctxFile->MemoryDescriptors->Run[i].PageCount = pDumpHeader64->PhysicalMemoryBlock.Run[i].PageCount;
            }

            vmmprintfvv(__FUNCTION__ ": DirectoryTableBase: 0x%I64X\n", pDumpHeader64->DirectoryTableBase);
            vmmprintfvv(__FUNCTION__ ": KdDebuggerDataBlock: 0x%I64X\n", pDumpHeader64->KdDebuggerDataBlock);
            vmmprintfvv(__FUNCTION__ ": PsActiveProcessHead: 0x%I64X\n", pDumpHeader64->PsActiveProcessHead);
            vmmprintfvv(__FUNCTION__ ": PsLoadedModuleList: 0x%I64X\n", pDumpHeader64->PsLoadedModuleList);

            ctxMain->cfg.paCR3 = pDumpHeader64->DirectoryTableBase & PAGE_MASK;
            // ctxVmm->kernel.paDTB = pDumpHeader->DirectoryTableBase & PAGE_MASK;
            // ctxVmm->kernel.vaPsLoadedModuleList = pDumpHeader->PsLoadedModuleList;
            // ctxVmm->kernel.vaKDBG = pDumpHeader->KdDebuggerDataBlock;
            // ctxVmm->kernel.vaBase
        }
        else {
            goto fail;
        }
    }

    Status = TRUE;
fail:

    vmmprintfv(__FUNCTION__ ": type=%d status=%d\n", ctxFile->Type, Status);
    if (Buffer) LocalFree(Buffer);

    return Status;
}

ULONG64
ConvertPhysicalAddressToFileOffset(
    PDEVICE_CONTEXT_FILE ctxFile,
    PMEM_IO_SCATTER_HEADER pMEM,
    PULONG maxCb
) {
    ULONG64 offset = pMEM->qwA;
    ULONG64 fileOffset = offset;

    ULONG cb = pMEM->cb;

    switch (ctxFile->Type) {
    case FileTypeRaw:
        return offset;
    case FileTypeDmp:
    case FileTypeDmp64:
        if (ctxFile->Type == FileTypeDmp) fileOffset += sizeof(DUMP_HEADER32);
        else if (ctxFile->Type == FileTypeDmp64) fileOffset += sizeof(DUMP_HEADER64);

        ULONG64 offsetPage = offset / PAGE_SIZE;
        ULONG64 deltaPages = 0;
        for (ULONG i = 0; i < ctxFile->MemoryDescriptors->NumberOfRuns; i++) {
            ULONG64 BasePage = ctxFile->MemoryDescriptors->Run[i].BasePage;
            ULONG64 LimitPage = BasePage + ctxFile->MemoryDescriptors->Run[i].PageCount;
            if ((offsetPage >= ctxFile->MemoryDescriptors->Run[i].BasePage) &&
                (offsetPage < LimitPage))
            {
                fileOffset = fileOffset - (BasePage * PAGE_SIZE) + (deltaPages * PAGE_SIZE);
                vmmprintfvv(__FUNCTION__ ": 0x%I64X -> 0x%I64X\n", offset, fileOffset);

                ULONG availableBytes = (ULONG)((LimitPage * PAGE_SIZE) - offset);

                *maxCb = min(cb, availableBytes);

                return fileOffset;
            }
            deltaPages += ctxFile->MemoryDescriptors->Run[i].PageCount;
        }

        vmmprintfvv(__FUNCTION__ ": INVALID: 0x%I64X -> 0x%I64X\n", offset, fileOffset);

        break;
    }

    return fileOffset;
}

VOID DeviceFile_ReadScatterMEM(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _Out_opt_ PDWORD pcMEMsRead)
{
    PDEVICE_CONTEXT_FILE ctxFile = (PDEVICE_CONTEXT_FILE)ctxMain->dev.hDevice;
    DWORD i, cbToRead, c = 0;
    PMEM_IO_SCATTER_HEADER pMEM;

    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];

        ULONG cbMax = 0;
        ULONG64 qwA = ConvertPhysicalAddressToFileOffset(ctxFile, pMEM, &cbMax);

        if(qwA >= ctxFile->cbFile) { continue; }
        cbToRead = (DWORD)min(pMEM->cb, ctxFile->cbFile - qwA);
        if(qwA != _ftelli64(ctxFile->pFile)) {
            if(_fseeki64(ctxFile->pFile, qwA, SEEK_SET)) { continue; }
        }
        pMEM->cb = (DWORD)fread(pMEM->pb, 1, pMEM->cbMax, ctxFile->pFile);
        if(ctxMain->cfg.fVerboseExtraTlp) {
            vmmprintf(
                "devicefile.c!DeviceFile_ReadScatterMEM: READ:\n" \
                "        file='%s' type=%d\n" \
                "        offset=%016llx fileoffset=%016llx req_len=%08x rsp_len=%08x\n", 
                ctxFile->szFileName, 
                ctxFile->Type,
                pMEM->qwA,
                qwA, 
                pMEM->cbMax, 
                pMEM->cb
            );
            Util_PrintHexAscii(pMEM->pb, pMEM->cb, 0);
        }
        c += (ppMEMs[i]->cb >= ppMEMs[i]->cbMax) ? 1 : 0;
    }

    if(pcMEMsRead) {
        *pcMEMsRead = c;
    }
}

VOID DeviceFile_Close()
{
    PDEVICE_CONTEXT_FILE ctxFile = (PDEVICE_CONTEXT_FILE)ctxMain->dev.hDevice;
    if(!ctxFile) { return; }
    fclose(ctxFile->pFile);

    if (ctxFile->MemoryDescriptors) {
        LocalFree(ctxFile->MemoryDescriptors);
        ctxFile->MemoryDescriptors = NULL;
    }

    LocalFree(ctxFile);
    ctxMain->dev.hDevice = 0;
}

BOOL DeviceFile_Open()
{
    PDEVICE_CONTEXT_FILE ctxFile;
    ctxFile = (PDEVICE_CONTEXT_FILE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FILE));
    if (!ctxFile) { return FALSE; }
    vmmprintfv("[!!!] Open %s\n", ctxMain->cfg.szDevTpOrFileName);
    // open backing file
    if (fopen_s(&ctxFile->pFile, ctxMain->cfg.szDevTpOrFileName, "rb") || !ctxFile->pFile) { goto fail; }
    if (_fseeki64(ctxFile->pFile, 0, SEEK_END)) { goto fail; }       // seek to end of file
    ctxFile->cbFile = _ftelli64(ctxFile->pFile);                    // get current file pointer
    if (ctxFile->cbFile < 0x1000) { goto fail; }

    if (!InitializeFileContextByType(ctxFile)) { goto fail; }

    ctxFile->szFileName = ctxMain->cfg.szDevTpOrFileName;
    ctxMain->dev.hDevice = (HANDLE)ctxFile;
    // set callback functions and fix up config
    ctxMain->dev.tp = VMM_DEVICE_FILE;
    ctxMain->dev.qwMaxSizeMemIo = 0x00100000;          // 1MB

    //
    // Address limit has to be computed differently for DMP files, and the file size does not apply.
    //
    if ((ctxFile->Type == FileTypeDmp) || (ctxFile->Type == FileTypeDmp64)) {
        ULONG64 Limit = 0;

        ULONG LastRun = ctxFile->MemoryDescriptors->NumberOfRuns - 1;
        Limit = ctxFile->MemoryDescriptors->Run[LastRun].BasePage + ctxFile->MemoryDescriptors->Run[LastRun].PageCount;
        Limit *= PAGE_SIZE;

        ctxMain->dev.paAddrMaxNative = Limit;
    }
    else {
        ctxMain->dev.paAddrMaxNative = ctxFile->cbFile;
    }

    ctxMain->dev.pfnClose = DeviceFile_Close;
    ctxMain->dev.pfnReadScatterMEM = DeviceFile_ReadScatterMEM;
    vmmprintfv("DEVICE: Successfully opened file: '%s'.\n", ctxMain->cfg.szDevTpOrFileName);
    return TRUE;
fail:
    if(ctxFile->pFile) { fclose(ctxFile->pFile); }
    LocalFree(ctxFile);
    printf("DEVICE: ERROR: Failed opening file: '%s'.\n", ctxMain->cfg.szDevTpOrFileName);
    return FALSE;
}
