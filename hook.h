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


//加载在TP前，初始化(获取未被hook的系统信息)
void InitBeforeTP();
//加载在TP启动后(获取TP原始代码)
void InitAfterTp();
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

//#define crc_jmp 0xcf6f6 //VM后的crc检测，jmp偏移，
#define AddrCRC1 0x1630
#define AddrCRC2 0x4082
#define AddrCRC3 0xd1a85
#define DebugPortReset1 0x2228
#define DebugPortReset2 0x6EA8
#define DebugPortCheck1 0xba4ca
#define DebugPortPop 0xbb0f0
#define NtGetContextThread_SSDT_INDEX 85 
//CRC校验
void FkCRC(BOOLEAN bFk);
void __stdcall FakeCRC3();

//Debug清零
void FkDebugReset(BOOLEAN bFk);
void __stdcall FakeDebugPort();
void __stdcall FakeDebugPortCheck();
void __stdcall FakeDebugPortPop();

//硬件断点
//对Context的硬件断点寄存器清零
void FkHardBreakPoint(BOOLEAN bFk);
void ZeroHardBreakPoint(PCONTEXT pContext,KPROCESSOR_MODE Mode);
void _stdcall FakeNtGetContextThread();
