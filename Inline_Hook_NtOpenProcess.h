#pragma once
#include <ntddk.h>
#include "util.h"

HANDLE Inline_NtOpenProcess_Id;



//MyNtOpenProcess
NTSTATUS MyNtOpenProcess(
   PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
     POBJECT_ATTRIBUTES ObjectAttributes,
  PCLIENT_ID ClientId
	);

void Inline_Hook_NtOpenProcess();
void Inline_unHook_NtOpenProcess();