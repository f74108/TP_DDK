#pragma once
#include "ntddk.h"

typedef NTSTATUS (*OB_SECURITY_METHOD)(
	IN PVOID Object,
	IN SECURITY_OPERATION_CODE OperationCode,
	IN PSECURITY_INFORMATION SecurityInformation,
	IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN OUT PULONG CapturedLength,
	IN OUT PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
	IN POOL_TYPE PoolType,
	IN PGENERIC_MAPPING GenericMapping,
	IN ULONG unk
	);



typedef NTSTATUS (__stdcall* ObOpenObjectByPointer)(
	IN   PVOID Object,
	IN      ULONG HandleAttributes,
	IN  PACCESS_STATE PassedAccessState,
	IN     ACCESS_MASK DesiredAccess,
	IN  POBJECT_TYPE ObjectType,
	IN     KPROCESSOR_MODE AccessMode,
	OUT    PHANDLE Handle
	);

////全局变量表
//typedef struct _Gloabal_Var {
//	ULONG addrNtReadVirtualMemory;
//	ULONG addrNtWriteVirtualMemory;
//	ULONG addrNtReadVirtualMemoryOffset;
//	ULONG addrNtWriteVirtualMemoryOffset;
//} global_Var;


 POBJECT_TYPE DbgkDebugObjectType;

void handleObjectHook(BOOLEAN bHook);

//加载image的回调函数
void LoadImageNotifyRoutine(IN PUNICODE_STRING FullName,
	IN HANDLE ProcessId,
	IN PIMAGE_INFO ImageInfo);


//加载在TP前，初始化
void InitBeforeTP();
//驱动卸载
void TP_DDK_Unload();

//恢复TP的KiAttachProcess //XP3
void ReSumeKiAttachProcess();

//绕过TP的NtOpenProcess
void FkNtOpenProcss();

//TP NtOpenProcess跳转到的裸函数
void __stdcall JmpNtOpenProcess(BOOLEAN bFk);

//绕过TP的NtOpenThread;
void FkNtOpenThread();

//TP NtOpenThread跳转到的裸函数
void __stdcall JmpNtOpenThread(BOOLEAN bFk);

//绕过TP的NtReadVirtualMemory
void FkNtReadVirtualMemory(BOOLEAN bFk);

void __stdcall FakeNtReadVirtualMemory();


//绕过TP的NtWriteVirtualMemory
void FkNtWriteVirtualMemory(BOOLEAN bFk);

void __stdcall FakeNtWriteVirtualMemory();


#define AddrCRC1 0x1630
#define AddrCRC2 0x4082
#define AddrCRC3 0xd1a85
#define DebugPortReset1 0x2228
//CRC校验
void FkCRC(BOOLEAN bFk);
void __stdcall FakeCRC3();