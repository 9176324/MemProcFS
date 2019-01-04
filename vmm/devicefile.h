// devicefile.h : definitions related to file backed memory acquisition device.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICEFILE_H__
#define __DEVICEFILE_H__
#include "vmm.h"
#include "dmp.h"

typedef enum tdFILE_TYPE {
    FileTypeRaw = 0,
    FileTypeDmp = 1,
    FileTypeDmp64 = 2
} FILE_TYPE;

typedef struct tdDEVICE_CONTEXT_FILE {
    FILE_TYPE Type;
    FILE *pFile;
    QWORD cbFile;
    LPSTR szFileName;

    PPHYSICAL_MEMORY_DESCRIPTOR64 MemoryDescriptors;
} DEVICE_CONTEXT_FILE, *PDEVICE_CONTEXT_FILE;


BOOL
InitializeFileContextByType(
    PDEVICE_CONTEXT_FILE ctxFile
);

ULONG64
ConvertPhysicalAddressToFileOffset(
    PDEVICE_CONTEXT_FILE ctxFile,
    PMEM_IO_SCATTER_HEADER pMEM,
    PULONG maxCb
);

/*
* Open a "connection" to the file.
* -- result
*/
BOOL DeviceFile_Open();

#endif /* __DEVICEFILE_H__ */
