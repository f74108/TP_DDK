
#include <ntddk.h>
#include "util.h"
#include "Inline_Hook_NtOpenProcess.h"
#include "hook.h"


void DDK_Unload(IN PDRIVER_OBJECT pDRIVER_OBJECT);
NTSTATUS ddk_DispatchRoutine_CONTROL(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp	);
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp);

#pragma INITCODE
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj,PUNICODE_STRING B)
{

	KdPrint(("TP_DDK Entry:....\n"));
	pDriverObj->DriverUnload=DDK_Unload;
	//注册派遣函数
	pDriverObj->MajorFunction[IRP_MJ_CREATE]=ddk_DispatchRoutine_CONTROL; //IRP_MJ_CREATE相关IRP处理数
	pDriverObj->MajorFunction[IRP_MJ_CLOSE]=DispatchClose; //IRP_MJ_CREATE相关IRP处理数
	pDriverObj->MajorFunction[IRP_MJ_READ]=ddk_DispatchRoutine_CONTROL; //IRP_MJ_CREATE相关IRP处理函数
	pDriverObj->MajorFunction[IRP_MJ_CLOSE]=ddk_DispatchRoutine_CONTROL; //IRP_MJ_CREATE相关IRP处理数
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]=ddk_DispatchRoutine_CONTROL; //IRP_MJ_CREATE相关		IRP处理函数
	
	CreateMyDevice(pDriverObj);//创建相应的设备

	
	//Inline_Hook_NtOpenProcess();
	//handleObjectHook(TRUE);
	//PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine); //加载载入映像回调
	InitBeforeTP();
 	KdPrint(("TesSafe: %x\n",GetModuleBase("tessafe.sys")));
	FkCRC(TRUE);
	return STATUS_SUCCESS;
}


void DDK_Unload(IN PDRIVER_OBJECT pDRIVER_OBJECT)
{
	PDEVICE_OBJECT pDev;
	UNICODE_STRING symLinkName;
	FkCRC(FALSE);
	//TP_DDK_Unload();
	//Inline_unHook_NtOpenProcess();
	//handleObjectHook(FALSE);
	//PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine); //卸载映像回调
	

	pDev=pDRIVER_OBJECT->DeviceObject;
	IoDeleteDevice(pDev); //删除设备
	RtlInitUnicodeString(&symLinkName,TP_symLinkName);	//删除符号链接名字
	IoDeleteSymbolicLink(&symLinkName);
	KdPrint(("设备卸载成功...\n"));
	KdPrint(("TP_DDK 驱动卸载成功...\n"));
}

NTSTATUS ddk_DispatchRoutine_CONTROL(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp	)
{
	ULONG info,mf;
	PIO_STACK_LOCATION stack;
	info=0;
	stack=IoGetCurrentIrpStackLocation(pIrp); //得到当前栈指针
	mf=stack->MajorFunction;
	switch(mf)
	{
	case IRP_MJ_DEVICE_CONTROL:
		{
			NTSTATUS status=STATUS_SUCCESS;
			//得到输入缓冲区大小
			ULONG cbin=stack->Parameters.DeviceIoControl.InputBufferLength;
			//得到输出缓冲区大小
			ULONG cbout=stack->Parameters.DeviceIoControl.OutputBufferLength;
			//得到IOCTL码
			ULONG code=stack->Parameters.DeviceIoControl.IoControlCode;

			switch(code)
			{
			case TEST_1:
				{
					int x,y;
					int *inBuffer=(int*)pIrp->AssociatedIrp.SystemBuffer;
					int *outBuffer=(int*)MmGetSystemAddressForMdlSafe(
						pIrp->MdlAddress,NormalPagePriority);
					//检测是否可读异常
					//ProbeForRead(inBuffer,cbin,__alignof(int));
					//获取输入buffer
					x=inBuffer[0];
					y=inBuffer[1];

					//检测是否可写异常
					//ProbeForWrite(OutBuffer,cbout,__alignof(int));
					//输出返回用户层	
					outBuffer[0]=x+y;
					KdPrint(("Call->add\n"));
					KdPrint(("x=%d,y=%d \n",x,y));
					break;
				}
			case Inline_NtOpenProcess_Hook_Code:
				{
					int pid=0;
					int* inBuffer=(int*)pIrp->AssociatedIrp.SystemBuffer;
					
					KdPrint(("PID:%d",*inBuffer));
					Inline_NtOpenProcess_Id=NULL;
					Inline_NtOpenProcess_Id=(HANDLE)(*inBuffer);
					break;
				}
			case TP_DDK_Enable_Code:
				{
					KdPrint(("TP_DDK_Enable_Code:\n"));
					ReSumeKiAttachProcess();
					FkNtOpenProcss(TRUE);
					FkNtOpenThread(TRUE);
					FkNtReadVirtualMemory(TRUE);
					FkNtWriteVirtualMemory(TRUE);
					break;
				}
			}

			break;
		}
	case IRP_MJ_CREATE:
		{
			break;
		}
	case  IRP_MJ_CLOSE:
		{
			KdPrint(("CLose Device...++++\n"));
			break;
		}
	case IRP_MJ_READ:
		{
			break;
		}
	}

	//对相应的IPR进行处理
	pIrp->IoStatus.Information=info; //设置操作的字节数为0，这里无实际意义
	pIrp->IoStatus.Status=STATUS_SUCCESS;//返回成功
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);//指示完成此IRP
	return STATUS_SUCCESS; 
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	KdPrint (("DispatchClose \n"));
	return STATUS_SUCCESS;
}