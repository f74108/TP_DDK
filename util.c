#include "util.h"


#pragma PAGECODE
ULONG MyGetFunAddress( IN PCWSTR FunctionName)
{
	UNICODE_STRING UniCodeFunctionName;
	RtlInitUnicodeString( &UniCodeFunctionName, FunctionName );
	return (ULONG)MmGetSystemRoutineAddress( &UniCodeFunctionName );   
}



#pragma PAGECODE
ULONG* GetSSDT_CurrAddr( void* func )
{
	ULONG SSDT_NtOpenProcess_Cur_Addr,index;
	index=SYSTEM_INDEX(func);
	SSDT_NtOpenProcess_Cur_Addr=(ULONG)KeServiceDescriptorTable->ServiceTableBase+0x4*index;
	SSDT_NtOpenProcess_Cur_Addr=(ULONG*)SSDT_NtOpenProcess_Cur_Addr;
	return SSDT_NtOpenProcess_Cur_Addr;
}

#pragma PAGECODE
ULONG GetVersion()
{
	ULONG rtn;
	ULONG MajorVersion,MinorVersion,BuildNumber;
	PsGetVersion(&MajorVersion,&MinorVersion,&BuildNumber,NULL);//系统版本.参数1主版本,参数2副版本,参数3时间序号,参数4字串
	rtn=MajorVersion;
	rtn=rtn *10;     
	rtn+=MinorVersion;   //主版本+副版本
	return rtn;
}


#pragma PAGECODE
NTSTATUS CreateMyDevice( IN PDRIVER_OBJECT pDrvierObj )
{
	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;

	//创建设备名称
	UNICODE_STRING devName;
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&devName,TP_DeviceName);

	//创建设备
	status=IoCreateDevice(pDrvierObj,0,&devName,FILE_DEVICE_UNKNOWN,0,TRUE,&pDevObj);
	if(!NT_SUCCESS(status))
	{
		switch(status)
		{
		case STATUS_INSUFFICIENT_RESOURCES:
			KdPrint(("资源不足 STATUS_INSUFFICIENT_RESOURCES"));
			break;
		case STATUS_OBJECT_NAME_EXISTS:
			KdPrint(("指定对象名存在"));
			break;
		case STATUS_OBJECT_NAME_COLLISION:
			KdPrint(("//对象名有冲突"));
			break;
		}
		KdPrint(("\n"));
		KdPrint(("设备创建失败...++++++++\n"));
		return status;
	}

	KdPrint(("设备创建成功...++++++++\n"));
	pDevObj->Flags |= DO_BUFFERED_IO;
	//创建符号链接
	RtlInitUnicodeString(&symLinkName,TP_symLinkName);
	status=IoCreateSymbolicLink(&symLinkName,&devName);
	if (!NT_SUCCESS(status)) /*status等于0*/
	{
		IoDeleteDevice( pDevObj );
		return status;
	}

	return STATUS_SUCCESS;
}

void DisableWP()
{
	__asm //去掉页面保护
	{
		cli
			push eax
			mov eax,cr0
			and eax,not 10000h //and eax,0FFFEFFFFh
			mov cr0,eax
			pop eax
	}
}

void EnableWP()
{
	__asm  //恢复页面保护
	{ 
		push eax
			mov eax,cr0
			or eax,10000h
			mov cr0,eax
			pop eax
			sti
	}
}

ULONG GetCodeLength( IN PVOID desFunc,IN ULONG NeedLengh )
{
	ULONG offset,codeLen;
	offset=0;
	codeLen=0;
	do 
	{
		codeLen=ade32_disasm((PVOID)((ULONG)desFunc+offset));
		if(codeLen==0)
			return 0;
		offset+=codeLen;
	} while (offset<NeedLengh);

	return offset;
}

//挂钩Function函数至FakeFunction
//JmpBuffer是FakeFunction跳转回Function的跳转缓冲区
BOOLEAN HookFunction(PVOID Function, PVOID FakeFunction, PUCHAR JmpBuffer)
{
	ULONG length;
	UCHAR jmpCode[5];
	PUCHAR temp;
	KIRQL Irql;

	length = ade32_get_code_length(Function, 5);
	if(length == 0)
		return FALSE;

	temp = (PUCHAR)Function + length;
	RtlCopyMemory(JmpBuffer, Function, length);

	JmpBuffer[length] = 0xe9;
	*(PULONG)(JmpBuffer + length + 1) = ((PUCHAR)Function + length - (JmpBuffer + length) - 5);

	jmpCode[0] = 0xe9;
	*(PULONG)(&jmpCode[1]) = (ULONG)((PUCHAR)FakeFunction - (PUCHAR)Function - 5);

	DisableWP();
	Irql=KeRaiseIrqlToDpcLevel();
	RtlCopyMemory(Function, jmpCode, 5);
	KeLowerIrql(Irql);
	EnableWP();

	return TRUE;
}

BOOLEAN UnhookFunction(PVOID Function, PUCHAR JmpBuffer)
{
	ULONG length;

	if(JmpBuffer[0] == 0)
		return TRUE;

	length = ade32_get_code_length(JmpBuffer, 5);
	if(length == 0)
		return FALSE;
	__asm int 3
	DisableWP();
	RtlCopyMemory(Function, JmpBuffer, length);
	EnableWP();

	RtlZeroMemory(JmpBuffer, length);

	return TRUE;
}

void WriteJmp( PVOID Function,PVOID fakeFunction,PUCHAR JmpBuffer )
{
	ULONG length;
	UCHAR jmpCode[5];
	PUCHAR temp;
	KIRQL Irql;

	length = ade32_get_code_length(Function, 5);
	if(length == 0)
		return FALSE;
	RtlCopyMemory(JmpBuffer, Function, length);

	jmpCode[0] = 0xe9;
	*(PULONG)(&jmpCode[1]) = (ULONG)((PUCHAR)fakeFunction - (PUCHAR)Function - 5);

	DisableWP();
	Irql=KeRaiseIrqlToDpcLevel();
	RtlCopyMemory(Function, jmpCode, 5);
	KeLowerIrql(Irql);
	EnableWP();
}


BOOLEAN  IsDnfProcess()
{
	PEPROCESS curProcess= PsGetCurrentProcess();
	PUCHAR pszCurName=PsGetProcessImageFileName(curProcess);
	if(_stricmp("dnf.exe",pszCurName)==0)
	{
		//KdPrint(("当前进程:%s\n",pszCurName));
		return TRUE;
	}
	return FALSE;
}

PSYSTEM_DESCRIPTOR_TABLE GetShadowTable()
{
	PUCHAR p;
	ULONG i,curAddr;
	PSYSTEM_DESCRIPTOR_TABLE rc;
	p=(PUCHAR)KeAddSystemServiceTable;
	for(i=0;i<100;i++)
	{
		curAddr=*(PULONG)(p+i);
		__try
		{
			if(MmIsAddressValid(curAddr) && MmIsAddressValid(curAddr+sizeof(SYSTEM_SERVICE_TABLE)-1))
			{
				if(memcmp(curAddr,KeServiceDescriptorTable,sizeof(SYSTEM_SERVICE_TABLE))==0)
				{
					if(curAddr==(ULONG)KeServiceDescriptorTable)
						continue;
					return curAddr;
				}
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{

		}
	}

	return NULL;
}

ULONG GetSysImageBase( PUCHAR moduleName )
{
	ULONG uImageBase;

}

NTSTATUS Ring0EnumProcess()
{
	ULONG   cbBuffer = 0x8000; //32k  
	PVOID   pSystemInfo;  
	NTSTATUS status;  
	PSYSTEM_PROCESS_INFORMATION pInfo;  

	//为查找进程分配足够的空间  
	do   
	{  
		pSystemInfo = ExAllocatePool(NonPagedPool, cbBuffer);  
		if (pSystemInfo == NULL)    //申请空间失败，返回  
		{  
			return 1;  
		}  
		status = ZwQuerySystemInformation(SystemProcessInformation, pSystemInfo, cbBuffer, NULL );  
		if (status == STATUS_INFO_LENGTH_MISMATCH) //空间不足  
		{  
			ExFreePool(pSystemInfo);  
			cbBuffer *= 2;  
		}  
		else if(!NT_SUCCESS(status))  
		{  
			ExFreePool(pSystemInfo);  
			return 1;  
		}  

	} while(status == STATUS_INFO_LENGTH_MISMATCH); //如果是空间不足，就一直循环  

	pInfo = (PSYSTEM_PROCESS_INFORMATION)pSystemInfo; //把得到的信息放到pInfo中  

	for (;;)  
	{  
		LPWSTR pszProcessName = pInfo->ImageName.Buffer;  
		if (pszProcessName == NULL)  
		{  
			pszProcessName = L"NULL";  
		}  
		KdPrint(("PID:%d, process name:%S\n", pInfo->ProcessId, pszProcessName)); 

		if (pInfo->NextEntryOffset == 0) //==0，说明到达进程链的尾部了  
		{  
			break;  
		}  
		pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset); //遍历  

	}  
	
	return STATUS_SUCCESS;  
}


ULONG GetModuleBase(PUCHAR moduleName)
{
	ULONG uSize=0x10000;
	ULONG ModulesCount=0,uImageBase=0,i;
	NTSTATUS status;
	PSYSTEM_MODULE_INFORMATION pModuleInfo;

	pModuleInfo=ExAllocatePool(NonPagedPool,uSize);
	if(pModuleInfo==NULL)
		return 0;
	status=ZwQuerySystemInformation(SystemModuleInformation,pModuleInfo,uSize,NULL);
	if(!NT_SUCCESS(status))
	{
		ExFreePool(pModuleInfo);
		return 0;
	}

	ModulesCount=pModuleInfo->ModulesCount;
	for(i=0;i<ModulesCount;i++)
	{
		PUCHAR fullName,fileName;
		fullName=pModuleInfo->Modules[i].Name;
		fileName=fullName+pModuleInfo->Modules[i].NameOffset;
		if(_stricmp(fileName,moduleName)==0)
		{
			uImageBase=pModuleInfo->Modules[i].ImageBaseAddress;
			break;
		}
	}

	ExFreePool(pModuleInfo);
	return uImageBase;
}

