#pragma once

#include "ntddk.h"
#include <WINDEF.H>
#include "ADE32.H"
#include "ctl_code.h"




#define TP_DeviceName L"\\Device\\TP_DDK"
#define TP_symLinkName L"\\??\\TP_DDK"
//////////////////////////////////////////////////////////////////////////
#define PAGECODE    code_seg("PAGE")   //分页
#define LOCKEDCODE   code_seg()
#define INITCODE     code_seg("INIT")   //执行就在内存中被卸载

#define PAGEDDATA    data_seg("PAGE")   //分页
#define LOCKEDDATA   data_seg()
#define INITDATA     data_seg("INIT")   //执行就在内存中被卸载

#define		SYSTEMSERVICE(ID)  KeServiceDescriptorTable->ServiceTableBase[ID]
#define        SYSTEM_SERVICE(_Func)        KeServiceDescriptorTable.ServiceTableBase[*(PULONG)((PUCHAR)_Func + 1)]
#define        SYSTEM_INDEX(_Func)                (*(PULONG)((PUCHAR)_Func + 1))
#define        IOCTL_START_PROTECTION        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define        C_MAXPROCNUMS                        12

//////////////////////////////////////////////////////////////////////////


/************************************************************************/
/* TypeDef                                                                     */
/************************************************************************/

typedef struct _SYSTEM_SERVICE_TABLE
{
	PULONG  ServiceTableBase;  // array of entry points
	PVOID  CounterTable;  // array of usage counters
	ULONG  ServiceLimit;    // number of table entries
	UCHAR*  ArgumentTable;  // array of byte counts
}SYSTEM_SERVICE_TABLE,*PSYSTEM_SERVICE_TABLE,**PPSYSTEM_SERVICE_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	SYSTEM_SERVICE_TABLE ntoskrnl;  // ntoskrnl.exe ( native api )
	SYSTEM_SERVICE_TABLE win32k;    // win32k.sys (gdi/user support)
	SYSTEM_SERVICE_TABLE Table3;    // not used
	SYSTEM_SERVICE_TABLE Table4;    // not used
}
SYSTEM_DESCRIPTOR_TABLE,*PSYSTEM_DESCRIPTOR_TABLE,**PPSYSTEM_DESCRIPTOR_TABLE;

//typedef struct _ServiceDescriptorTable
//{
//	PVOID ServiceTableBase; //System Service Dispatch Table 的基地址 
//	PVOID ServiceCounterTable ;//包含着 SSDT 中每个服务被调用次数的计数器。这个计数器一般由sysenter 更新。
//	unsigned int NumberOfServices;//由 ServiceTableBase 描述的服务的数目。 
//	PVOID ParamTableBase;//包含每个系统服务参数字节数表的基地址-系统服务参数表 
//} *PServiceDescriptorTable;


typedef enum _SYSTEM_INFORMATION_CLASS {  
	SystemBasicInformation,  
	SystemProcessorInformation,  
	SystemPerformanceInformation,  
	SystemTimeOfDayInformation,  
	SystemPathInformation,  
	SystemProcessInformation, //5  
	SystemCallCountInformation,  
	SystemDeviceInformation,  
	SystemProcessorPerformanceInformation,  
	SystemFlagsInformation,  
	SystemCallTimeInformation,  
	SystemModuleInformation,  
	SystemLocksInformation,  
	SystemStackTraceInformation,  
	SystemPagedPoolInformation,  
	SystemNonPagedPoolInformation,  
	SystemHandleInformation,  
	SystemObjectInformation,  
	SystemPageFileInformation,  
	SystemVdmInstemulInformation,  
	SystemVdmBopInformation,  
	SystemFileCacheInformation,  
	SystemPoolTagInformation,  
	SystemInterruptInformation,  
	SystemDpcBehaviorInformation,  
	SystemFullMemoryInformation,  
	SystemLoadGdiDriverInformation,  
	SystemUnloadGdiDriverInformation,  
	SystemTimeAdjustmentInformation,  
	SystemSummaryMemoryInformation,  
	SystemNextEventIdInformation,  
	SystemEventIdsInformation,  
	SystemCrashDumpInformation,  
	SystemExceptionInformation,  
	SystemCrashDumpStateInformation,  
	SystemKernelDebuggerInformation,  
	SystemContextSwitchInformation,  
	SystemRegistryQuotaInformation,  
	SystemExtendServiceTableInformation,  
	SystemPrioritySeperation,  
	SystemPlugPlayBusInformation,  
	SystemDockInformation,  
	SystemPowerInformation2,  
	SystemProcessorSpeedInformation,  
	SystemCurrentTimeZoneInformation,  
	SystemLookasideInformation  
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;  

typedef struct _SYSTEM_THREAD_INFORMATION {  
	LARGE_INTEGER           KernelTime;  
	LARGE_INTEGER           UserTime;  
	LARGE_INTEGER           CreateTime;  
	ULONG                   WaitTime;  
	PVOID                   StartAddress;  
	CLIENT_ID               ClientId;  
	KPRIORITY               Priority;  
	LONG                    BasePriority;  
	ULONG                   ContextSwitchCount;  
	ULONG                   State;  
	KWAIT_REASON            WaitReason;  
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION; 

typedef struct _SYSTEM_PROCESS_INFORMATION {  
	ULONG                   NextEntryOffset;  
	ULONG                   NumberOfThreads;  
	LARGE_INTEGER           Reserved[3];  
	LARGE_INTEGER           CreateTime;  
	LARGE_INTEGER           UserTime;  
	LARGE_INTEGER           KernelTime;  
	UNICODE_STRING          ImageName;  
	KPRIORITY               BasePriority;  
	HANDLE                  ProcessId;  
	HANDLE                  InheritedFromProcessId;  
	ULONG                   HandleCount;  
	ULONG                   Reserved2[2];  
	ULONG                   PrivatePageCount;  
	VM_COUNTERS             VirtualMemoryCounters;  
	IO_COUNTERS             IoCounters;  
	SYSTEM_THREAD_INFORMATION           Threads[0];  
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;  

typedef struct _SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	BYTE                 Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[0];

} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
////////////////////////////////Global variable ///////////////////////////////////////////////
extern PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;
extern PSYSTEM_DESCRIPTOR_TABLE KeServiceDescriptorTableShadow;

// 定义NtOpenProcess的原型
typedef NTSTATUS (__stdcall *NTOPENPROCESS)(
	OUT		PHANDLE ProcessHandle,
	IN      ACCESS_MASK DesiredAccess,
	IN      POBJECT_ATTRIBUTES ObjectAttributes,
	IN		PCLIENT_ID ClientId
	);

EXTERN_C __declspec(dllimport) NTSTATUS NtOpenThread(
	OUT  PHANDLE ThreadHandle,
	IN   ACCESS_MASK DesiredAccess,
	IN   POBJECT_ATTRIBUTES ObjectAttributes,
	IN   PCLIENT_ID ClientId
	);

 
EXTERN_C NTKERNELAPI
	BOOLEAN
	KeAddSystemServiceTable(
	IN PULONG_PTR Base,
	IN PULONG Count OPTIONAL,
	IN ULONG Limit,
	IN PUCHAR Number,
	IN ULONG Index
	);

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(   
	IN ULONG SystemInformationClass,   
	IN PVOID SystemInformation,   
	IN ULONG SystemInformationLength,   
	OUT PULONG ReturnLength); 

//NTKERNELAPI
//	VOID
//	KeStackAttachProcess (
//	IN PRKPROCESS PROCESS,
//	OUT PRKAPC_STATE ApcState
//	);


UCHAR *
	PsGetProcessImageFileName(
	__in PEPROCESS Process
	);

//保存5字节代码的结构 
#pragma pack(1) 
typedef struct _TOP5CODE 
{ 
	UCHAR instruction; //指令
	ULONG address; //地址 
}TOP5CODE,*PTOP5CODE; 
#pragma pack()

//////////////////////////////////////////////////////////////////////
//  名称:  MyGetFunAddress
//  功能:  获取函数地址
//  参数:  函数名称字符串指针
//  返回:  函数地址
//////////////////////////////////////////////////////////////////////
ULONG MyGetFunAddress( IN PCWSTR FunctionName);


//ring0 遍历进程
NTSTATUS Ring0EnumProcess();

//获取模块基地址
ULONG GetModuleBase(PUCHAR moduleName);

//************************************
// Method:    GetSSDT_CurrAddr
// FullName:  GetSSDT_CurrAddr
// Access:    public 
// Returns:   ULONG*
// Qualifier:获取SSDT函数当前地址
// Parameter: void * func
//************************************
ULONG* GetSSDT_CurrAddr(void* func);

PSYSTEM_DESCRIPTOR_TABLE GetShadowTable();

//获取系统版本号
ULONG GetVersion();

//判断当前进程是否为DNF.exe
BOOLEAN  IsDnfProcess();

//去掉页面保护
void DisableWP();

 //恢复页面保护
void EnableWP();

//************************************
// Method:    CreateMyDevice
// FullName:  CreateMyDevice
// Access:    public 
// Returns:   NTSTATUS
// Qualifier:创建设备
// Parameter: IN PDRIVER_OBJECT pDrvierObj
//************************************
NTSTATUS CreateMyDevice(IN PDRIVER_OBJECT pDrvierObj);

//计算hook长度
ULONG GetCodeLength(IN PVOID desFunc,IN ULONG NeedLengh);

//挂钩Function函数至FakeFunction
//JmpBuffer是FakeFunction跳转回Function的跳转缓冲区
BOOLEAN HookFunction(PVOID Function, PVOID FakeFunction, PUCHAR JmpBuffer);

BOOLEAN UnhookFunction(PVOID Function, PUCHAR JmpBuffer);

//纯粹实现的跳转
void WriteJmp( PVOID Function,PVOID fakeFunction,PUCHAR JmpBuffer );


