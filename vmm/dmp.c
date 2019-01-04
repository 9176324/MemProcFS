// dmp.c : implementation related to Microsoft crash dump header.
//
// (c) Matt Suiche, 2019
// Author: Matt Suiche, msuiche@comae.com
//
#include "dmp.h"
#include "devicefile.h"
#include "util.h"
#include "vmm.h"

BOOL
ReadFileAt(
    FILE *fp,
    ULONG64 offset,
    PVOID *buffer,
    ULONG buffer_size
)
{
    size_t size = PAGE_SIZE;
    size_t result = 0;
    BOOL status = FALSE;

    if (buffer_size) size = buffer_size;

    if (_fseeki64(fp, offset, SEEK_SET)) {
        vmmprintfv("error: can't change the offset to 0x%I64dx.\n", offset);
        goto cleanup;
    }

    result = fread(buffer, 1, size, fp);
    if (result != size) {
        // printf("error: can't read data at 0x%llx. result = 0x%zx\n", offset, result);
        goto cleanup;
    }

    status = TRUE;

cleanup:
    return status;
}