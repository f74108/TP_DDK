
#include <ntddk.h>
#include "util.h"
#include "hook.h"


void DDK_Unload(IN PDRIVER_OBJECT pDRIVER_OBJECT);
NTSTATUS  Comm_Create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS  Comm_Close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS Comm_Default(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS Comm_IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS COMM_DirectOutIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);
NTSTATUS COMM_DirectInIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);
NTSTATUS COMM_BufferedIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);
NTSTATUS COMM_NeitherIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);
NTSTATUS COMM_TP_DDK(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj,PUNICODE_STRING B)
{

	KdPrint(("TP_DDK Entry:....\n"));


	pDriverObj->DriverUnload=DDK_Unload;
	//注册派遣函数
	pDriverObj->MajorFunction[IRP_MJ_CREATE]=Comm_Create; 
	pDriverObj->MajorFunction[IRP_MJ_CLOSE]=Comm_Close;
	pDriverObj->MajorFunction[IRP_MJ_READ]=Comm_Default;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]=Comm_IoControl;

	if(!NT_SUCCESS(CreateMyDevice(pDriverObj))) //创建相应的设备
		KdPrint(("创建设备失败..\n"));
	//Inline_Hook_NtOpenProcess();
	//handleObjectHook(TRUE);
	//PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine); //加载载入映像回调
	InitAfterTp();

	return STATUS_SUCCESS;
}


void DDK_Unload(IN PDRIVER_OBJECT pDRIVER_OBJECT)
{
	UNICODE_STRING symLinkName;
	if(pDRIVER_OBJECT->DeviceObject!=NULL)
		IoDeleteDevice(pDRIVER_OBJECT->DeviceObject); //删除设备
	RtlInitUnicodeString(&symLinkName,L"\\??\\TP_DDK");	//删除符号链接名字
	IoDeleteSymbolicLink(&symLinkName);
	KdPrint(("设备卸载成功...\n"));
	KdPrint(("TP_DDK 驱动卸载成功...\n"));
}

NTSTATUS Comm_IoControl(IN PDEVICE_OBJECT pDevobj,IN PIRP pIrp	)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION irpStack = NULL;
	UINT sizeofWrite = 0;

	//KdPrint(("Comm_IoControl\n"));
	irpStack=IoGetCurrentIrpStackLocation(pIrp); //得到当前栈指针

	if(irpStack)
	{
		switch(irpStack->Parameters.DeviceIoControl.IoControlCode)
		{
			case IOCTL_COMM_DIRECT_IN_IO:	//直接输入缓冲输出I/O(METHOD_IN_DIRECT)
				status=COMM_DirectInIo(pIrp,irpStack,&sizeofWrite);
				break;

			case  IOCTL_COMM_DIRECT_OUT_IO:	//缓冲输入直接输出I/O(METHOD_OUT_DIRECT)
				status=COMM_DirectOutIo(pIrp,irpStack,&sizeofWrite);
				break;

			case  IOCTL_COMM_BUFFERED_IO:	//输入输出缓冲I/O(METHOD_BUFFERED)
				status=COMM_BufferedIo(pIrp,irpStack,&sizeofWrite);
				break;

			case IOCTL_COMM_NEITHER_IO:		//上面三种方法都不是(METHOD_NEITHER)
				status=COMM_NeitherIo(pIrp,irpStack,&sizeofWrite);
				break;

			case IOCTL_TP_DDK_ENABLE:
				status=COMM_TP_DDK(pIrp,irpStack,&sizeofWrite);
				break;
		}
	}

	/*
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
					//__asm int 3
					//KdPrint(("TP_DDK_Enable_Code:\n"));
					
					InitAfterTp();
					FkNtOpenProcss(TRUE);
					FkNtOpenThread(TRUE);
					FkCRC(TRUE);
					//FkDebugReset(TRUE);
					ReSumeKiAttachProcess();

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
	*/
	//对相应的IPR进行处理

	pIrp->IoStatus.Information=sizeofWrite;
	pIrp->IoStatus.Status=status;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);//指示完成此IRP
	return status; 
}

NTSTATUS Comm_Close(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Comm_Create(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return pIrp->IoStatus.Status;
}

NTSTATUS Comm_Default(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return pIrp->IoStatus.Status;
}


NTSTATUS COMM_DirectInIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pInputBuffer, pOutputBuffer;
	ULONG  outputLength, inputLength;

	outputLength=pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
	inputLength=pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	pInputBuffer=Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = NULL;

	if(Irp->MdlAddress)
		pOutputBuffer=MmGetSystemAddressForMdlSafe(Irp->MdlAddress,NormalPagePriority);
	
	if(pOutputBuffer && pOutputBuffer)
	{
		//KdPrint(("IOCTL_COMM_DIRECT_IN_IO-> UserModeMessage = %s \n", pInputBuffer));
		//RtlCopyMemory(pOutputBuffer,pInputBuffer,outputLength);
		*sizeofWrite = outputLength;

		InitAfterTp();
		status = STATUS_SUCCESS;
	}

	return status;
}

NTSTATUS COMM_DirectOutIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pInputBuffer, pOutputBuffer;
	ULONG  outputLength, inputLength;

	//KdPrint(("COMM_DirectOutIo\r\n"));

	outputLength = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
	inputLength  = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = NULL;

	if(Irp->MdlAddress)
		pOutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

	if(pInputBuffer && pOutputBuffer)
	{                                                          
		KdPrint(("COMM_DirectOutIo UserModeMessage = '%s'", pInputBuffer));
		RtlCopyMemory(pOutputBuffer, pInputBuffer, outputLength);
		*sizeofWrite = outputLength;
		status = STATUS_SUCCESS;
	}
	return status;
}

NTSTATUS COMM_BufferedIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pInputBuffer, pOutputBuffer;
	ULONG  outputLength, inputLength;

	KdPrint(("COMM_BufferedIo\r\n"));

	outputLength = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
	inputLength  = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;

	if(pInputBuffer && pOutputBuffer)
	{              
		KdPrint(("COMM_BufferedIo UserModeMessage = '%s'", pInputBuffer));
		//RtlCopyMemory(pOutputBuffer, pInputBuffer, outputLength);
		*sizeofWrite = outputLength;


		status = STATUS_SUCCESS;
	}
	return status;
}

NTSTATUS COMM_NeitherIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pInputBuffer, pOutputBuffer;
	ULONG  outputLength, inputLength;

	KdPrint(("COMM_NeitherIo\r\n"));

	outputLength  = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
	inputLength   = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	pInputBuffer  = pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;
	pOutputBuffer = Irp->UserBuffer;

	if(pInputBuffer && pOutputBuffer)
	{              
		KdPrint(("COMM_NeitherIo UserModeMessage = '%s'", pInputBuffer));
		RtlCopyMemory(pOutputBuffer, pInputBuffer, outputLength);
		*sizeofWrite = outputLength;
		status = STATUS_SUCCESS;
	}
	return status;
}

NTSTATUS COMM_TP_DDK(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pInputBuffer, pOutputBuffer;
	ULONG  outputLength, inputLength;

	//KdPrint(("COMM_TP_DDK\r\n"));

	status = STATUS_SUCCESS;
	
	return status;
}