#include "hook.h"
#include "util.h"


OB_SECURITY_METHOD g_fnSecurityProcedure=NULL;


 NTSTATUS MySecurityProcedure(
	IN PVOID Object,
	IN SECURITY_OPERATION_CODE OperationCode,
	IN PSECURITY_INFORMATION SecurityInformation,
	IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN OUT PULONG CapturedLength,
	IN OUT PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
	IN POOL_TYPE PoolType,
	IN PGENERIC_MAPPING GenericMapping,
	IN ULONG unk
	)
 {
	 PCHAR pTargetName;
	 //KdPrint(("++Current Eprocess:%x  Objcet:%x++\n",IoGetCurrentProcess(),Object));
	 KdPrint(("++Current Eprocess:%s  Objcet:%s++\n",
		 PsGetProcessImageFileName(IoGetCurrentProcess()),
		 PsGetProcessImageFileName((PEPROCESS)Object)));
	 pTargetName=PsGetProcessImageFileName((PEPROCESS)Object);
	 if(_stricmp(pTargetName,"calc.exe")==0)
		 return STATUS_INVALID_PARAMETER;

	 return g_fnSecurityProcedure(
		 Object,
		 OperationCode,
		 SecurityInformation,
		 SecurityDescriptor,
		 CapturedLength,
		 ObjectsSecurityDescriptor,
		 PoolType,GenericMapping,
		 unk);
 }

void handleObjectHook(BOOLEAN bHook)
{
	PVOID TypeInfo=(PVOID)((ULONG)*PsProcessType+0x60);
	//PVOID TypeInfo=(PVOID)((ULONG)DbgkDebugObjectType+0x60);
	if(bHook)
	{
		g_fnSecurityProcedure=(OB_SECURITY_METHOD)*(PULONG)((ULONG)TypeInfo+0x40);
		*(PULONG)((ULONG)TypeInfo+0x40)=(ULONG)MySecurityProcedure;
	}
	else
	{
		*(PULONG)((ULONG)TypeInfo+0x40)=(ULONG)g_fnSecurityProcedure;
	}
}

void LoadImageNotifyRoutine(IN PUNICODE_STRING FullName,
							IN HANDLE ProcessId,
							IN PIMAGE_INFO ImageInfo)
{
	KIRQL Irql;
	ULONG uImageBase;
	if(wcsstr(FullName->Buffer,L"TesSafe.sys")!=0)
	{
		__asm //去掉页面保护
		{
			push eax
			cli
				mov eax,cr0
				and eax,not 10000h //and eax,0FFFEFFFFh
				mov cr0,eax
				pop eax
		}
		//提升IRQL中断级
		Irql=KeRaiseIrqlToDpcLevel();

		*(UCHAR*)KdDisableDebugger=0xC3;
		uImageBase=ImageInfo->ImageBase;
		*(PUCHAR)(uImageBase+0x7031)=0x74;
		*(PUCHAR)(uImageBase+0x715f)=0xEB;

		KeLowerIrql(Irql);
		__asm  //恢复页面保护
		{ 
			push eax
			mov eax,cr0
				or eax,10000h
				mov cr0,eax
				sti
			pop eax
		}
		KdPrint(("TesSafe.sys 去除KdDisableDebugger完毕\n"));
	}

	return;
}


//全局变量
PSYSTEM_DESCRIPTOR_TABLE KeServiceDescriptorTableShadow; //sstd Shadow

ULONG NtOpenProcessCodeLen=0; //NtOpenProcess 跳转修改的代码长度
UCHAR JmpBackNtOpenProcess[20]={0};
ULONG g_uNtOpenProcessInjectAddr;

UCHAR JmpBackNtOpenThread[20]={0};
ULONG g_uNtOpenThreadInjectAddr;

ULONG g_uNtReadVirtualMemoryAddr;
ULONG g_uNtReadVirtualMemoryAddr_offest3;
ULONG g_uNtWriteVirtualMemoryAddr;
ULONG g_uNtWriteVirtualMemoryAddr_offset3;
UCHAR g_KiAttachProcess_10[10]={0};

UCHAR JmpBackCRC3[25]={0};
ULONG g_uCRC3Ret=0; //CRC3 TP原始jmp
ULONG g_uDebugPort_Reset1=0; //debugPort清零函数1
ULONG g_uDebugPort_Reset1_4; //debugPort清零函数1 原前四节内容,用来骗过CRC检测
ULONG g_uDebugPort_Reset2=0; //debugPort清零函数2
ULONG g_uDebugPort_Reset2_4; //debugPort清零函数2 原前四节内容,用来骗过CRC检测
ULONG g_uDebugPort_Pointer;   //debugPort指针
ULONG g_uDebugPortRet;       //debugPort检测1的跳回地址
UCHAR JmpBackDebugCheck[20]={0};
ULONG g_uDebugPortPopRet; //debugPort还原POP的跳回地址
UCHAR JmpBackDebugPop[20]={0};

ULONG g_Process_fnObOpenObjectByPointer=0; //ObOpenObjectByPointer 函数地址
ULONG g_uNtGetContextThreadAddr=0; //NtGetContextThread函数地址
ULONG g_uNtGetContextThreadInjectAddr=0; //NtGetContextThread函数跳转地址
UCHAR JmpBackNtGetContextThread[20]={0};
//加载在TP前，初始化
void InitBeforeTP()
{
	ULONG addrNtReadMemory,addrNtWriteMemory,uImageBase,
		_KeStackAttachProcess,_Cur_KeStackAttachProcess,KiAttachProcess_bytes,_KiAttachProcess;

	uImageBase=GetModuleBase("TesSafe.sys");
	if(uImageBase>0)
	{
		KdPrint(("TP_DDK:TesSafe模块已被加载,第一初始化失败\n"));
		return;
	}

	
	g_uNtGetContextThreadAddr=SYSTEMSERVICE(NtGetContextThread_SSDT_INDEX);
	addrNtReadMemory=(ULONG)KeServiceDescriptorTable->ServiceTableBase+186*4;
	addrNtWriteMemory=(ULONG)KeServiceDescriptorTable->ServiceTableBase+277*4;

	addrNtReadMemory=*(PULONG)addrNtReadMemory;
	addrNtWriteMemory=*(PULONG)addrNtWriteMemory;

	g_uNtReadVirtualMemoryAddr=addrNtReadMemory;
	g_uNtWriteVirtualMemoryAddr=addrNtWriteMemory;
	g_uNtReadVirtualMemoryAddr_offest3=*(PULONG)(addrNtReadMemory+3);
	g_uNtWriteVirtualMemoryAddr_offset3=*(PULONG)(addrNtWriteMemory+3);

	//保存KiAttachProcess前10字节
	 _KeStackAttachProcess=MyGetFunAddress(L"KeStackAttachProcess");
	 _Cur_KeStackAttachProcess=_KeStackAttachProcess+0x65;
	 KiAttachProcess_bytes=*(PULONG)(_Cur_KeStackAttachProcess+1);
	 _KiAttachProcess=KiAttachProcess_bytes+_Cur_KeStackAttachProcess+5;
	RtlCopyMemory(g_KiAttachProcess_10,_KiAttachProcess,10);
	KeServiceDescriptorTableShadow=(ULONG)KeServiceDescriptorTable-0x40;
}
//加载在TP启动后(获取TP原始代码)
void InitAfterTp()
{
	ULONG uImageBase,bytes_jmp;
	ULONG crc3,dbgPortCheck1,dbgPortPop;
	LOADED_KERNEL_INFO loadedkernelInfo;
	ULONG rvaNtRead,rvaNtWrite,rvaKiAttachProcess;
	ULONG _KeStackAttachProcess,_Cur_KeStackAttachProcess,
		KiAttachProcess_bytes,_KiAttachProcess;


	uImageBase=GetModuleBase("TesSafe.sys");
	if(uImageBase==0)
	{
		KdPrint(("TP_DDK:获取TesSafe模块失败,第二初始化失败\n"));
		return;
	}

	if (!NT_SUCCESS(LoadKernelFile(&loadedkernelInfo)))
	{
		KdPrint(("TP_DDK:载入新内核失败!\n"));
		return;
	}

	rvaNtRead=GetOrgSSdtFuncRVA(SSDT_INDEX_NtReadVirtualMemory,&loadedkernelInfo);
	rvaNtWrite=GetOrgSSdtFuncRVA(SSDT_INDEX_NtWriteVirtualMemory,&loadedkernelInfo);
	g_uNtReadVirtualMemoryAddr=(ULONG)loadedkernelInfo.OriginalKernelBase+rvaNtRead;
	g_uNtWriteVirtualMemoryAddr=(ULONG)loadedkernelInfo.OriginalKernelBase+rvaNtWrite;
	g_uNtReadVirtualMemoryAddr_offest3=*(PULONG)((ULONG)loadedkernelInfo.NewKernelBase+rvaNtRead+3)-LoadBase;
	g_uNtWriteVirtualMemoryAddr_offset3=*(PULONG)((ULONG)loadedkernelInfo.NewKernelBase+rvaNtWrite+3)-LoadBase;

	//保存KiAttachProcess前10字节
	_KeStackAttachProcess=MyGetFunAddress(L"KeStackAttachProcess");
	_Cur_KeStackAttachProcess=_KeStackAttachProcess+0x65;
	KiAttachProcess_bytes=*(PULONG)(_Cur_KeStackAttachProcess+1);
	_KiAttachProcess=KiAttachProcess_bytes+_Cur_KeStackAttachProcess+5;
	rvaKiAttachProcess=_KiAttachProcess-(ULONG)loadedkernelInfo.OriginalKernelBase;
	_KiAttachProcess=(ULONG)loadedkernelInfo.NewKernelBase+rvaKiAttachProcess;
	RtlCopyMemory(g_KiAttachProcess_10,_KiAttachProcess,10);

	g_uNtGetContextThreadAddr=SYSTEMSERVICE(NtGetContextThread_SSDT_INDEX);
	//释放新加载的内核
	if(loadedkernelInfo.NewKernelBase!=NULL)
		ExFreePool(loadedkernelInfo.NewKernelBase);

	KeServiceDescriptorTableShadow=(ULONG)KeServiceDescriptorTable-0x40;

	crc3=uImageBase+AddrCRC3;
	bytes_jmp=*(PULONG)(crc3+3);
	//bytes_jmp=g_uCRC3Ret-(crc3+2)-5
	g_uCRC3Ret= bytes_jmp+(crc3+2)+5;  //保存CRC检测3的原始Jmp
	g_uDebugPort_Reset1=uImageBase+DebugPortReset1; //初始化清零函数1地址
	g_uDebugPort_Reset1_4=*(PULONG)g_uDebugPort_Reset1; //保存清零函数1前四节
	g_uDebugPort_Reset2=uImageBase+DebugPortReset2; //初始化清零函数2地址
	g_uDebugPort_Reset2_4=*(PULONG)g_uDebugPort_Reset2; //保存清零函数2前四节

	dbgPortCheck1=uImageBase+DebugPortCheck1;
	bytes_jmp=*(PULONG)(dbgPortCheck1+3);
	//bytes_jmp=g_uDebugPortRet-(dbgPortCheck1+2)-5
	g_uDebugPortRet= bytes_jmp+(dbgPortCheck1+2)+5; //保存debugPort检测1的原始Jmp
	g_uDebugPort_Pointer=GetProcessByName(GameProcessName)+
					GetPlantformDependentInfo(DebugPort_OFFSET);//获取debugPort指针

		
	dbgPortPop=uImageBase+DebugPortPop;
	bytes_jmp=*(PULONG)(dbgPortPop+3);
	//bytes_jmp=g_uDebugPortPopRet-(dbgPortPop+2)-5
	g_uDebugPortPopRet= bytes_jmp+(dbgPortPop+2)+5; //保存debugPort清零POP的原始Jmp

	FkCRC(TRUE);
	FkDebugReset(TRUE);
	FkNtOpenProcss(TRUE);
	FkNtOpenThread(TRUE);
	ReSumeKiAttachProcess();
	FkNtWriteVirtualMemory(TRUE);
	FkNtReadVirtualMemory(TRUE);
	FkHardBreakPoint(TRUE);
}

//驱动卸载
void TP_DDK_Unload()
{
	FkNtOpenThread(FALSE);
	FkNtOpenProcss(FALSE);
	FkNtReadVirtualMemory(FALSE);
	FkNtWriteVirtualMemory(FALSE);
	
}

void ReSumeKiAttachProcess()
{
	KIRQL Irql;
	ULONG _KeStackAttachProcess, _Cur_KeStackAttachProcess, _KiAttachProcess;
	ULONG bytes;
	//UCHAR orgBytes[10]={0x8B,0xff,0x55,0x8b,0xec,0x53,0x56,0x8b,0x75,0x8};

	_KeStackAttachProcess=MyGetFunAddress(L"KeStackAttachProcess");
	_Cur_KeStackAttachProcess=_KeStackAttachProcess+0x65;
	bytes=*(PULONG)(_Cur_KeStackAttachProcess+1);
	//KiAttachProcess-Cur_KeStackAttachProcess-5=bytes;
	_KiAttachProcess=bytes+_Cur_KeStackAttachProcess+5;

		DisableWP();
		Irql=KeRaiseIrqlToDpcLevel();
		RtlCopyMemory((PVOID)_KiAttachProcess,(PVOID)g_KiAttachProcess_10,10);

		KeLowerIrql(Irql);
		EnableWP();
		KdPrint(("TP_DDK: 解除KiAttachProcess\n"));
}

void FkNtOpenProcss(BOOLEAN bFk)
{
	KIRQL Irql;
	BOOLEAN bFound;
	PUCHAR p;
	ULONG i;
	bFound=FALSE;
	p=(PUCHAR)NtOpenProcess;;
	i=0;
	g_Process_fnObOpenObjectByPointer=MyGetFunAddress(L"ObOpenObjectByPointer");

	if(bFk)
	{
		ULONG bytes=0;
		while(i<0x300)
		{
			if (*p==0x50 && 
				*(p+1)==0xff &&
				*(p+4)==0xff &&
				*(p+7)==0xE8)
			{
				bFound=TRUE;
				break;
			}
			i++;
			p++;
		}
		if(!bFound)
		{
			KdPrint(("TP_DDK: 找不到 ObOpenObjectByPointer 函数地址\n"));
			return;
		}
		g_uNtOpenProcessInjectAddr=p+1;

		NtOpenProcessCodeLen=ade32_get_code_length(g_uNtOpenProcessInjectAddr,5);

		DisableWP();
		Irql=KeRaiseIrqlToDpcLevel();
		RtlCopyMemory((PVOID)JmpNtOpenProcess,(PVOID)g_uNtOpenProcessInjectAddr,NtOpenProcessCodeLen);
		KeLowerIrql(Irql);
		EnableWP();
		WriteJmp((PVOID)g_uNtOpenProcessInjectAddr,JmpNtOpenProcess,JmpBackNtOpenProcess);

		KdPrint(("TP_DDK: 解除NtOpenProcess保护!\n"));
	}
	else
	{
		if(!MmIsAddressValid(JmpNtOpenProcess))
			return;
		UnhookFunction((PVOID)g_uNtOpenProcessInjectAddr,JmpBackNtOpenProcess);
		
		KdPrint(("TP_DDK: 还原NtOpenProcess保护!\n"));
	}
	

}


 __declspec(naked) void __stdcall JmpNtOpenProcess()
 {
	 __asm
	 {
		 nop
		 nop
		 nop
		 nop
		 nop
		 nop
		 nop
		 nop
		 pushad
		 pushfd
		 call IsDnfProcess
		 cmp al,0
		 je NotNDF
		 popfd
		 popad
		
		 mov eax,g_uNtOpenProcessInjectAddr
		 add eax,NtOpenProcessCodeLen;
		 jmp eax //DNF进程，执行TP的流程
NotNDF:	
		 popfd
		 popad
		 mov eax,[g_Process_fnObOpenObjectByPointer]
		 call eax //调用原生ObOpenObjectByPointer
		 mov edi, [g_uNtOpenProcessInjectAddr]
		 add edi,[NtOpenProcessCodeLen]
		 add edi,5
		 jmp edi	
	 }
 }


 ULONG NtOpenThreadCodeLen=0; //NtOpenProcess 跳转修改的代码长度
 ULONG g_Thread_fnObOpenObjectByPointer=0; //ObOpenObjectByPointer 函数地址
 ULONG g_Thread_HookObOpenObjectByPointer; //写入jmp的地址
 void FkNtOpenThread(BOOLEAN bFk)
 {
	 KIRQL Irql;
	 BOOLEAN bFound;
	 PUCHAR p;
	 ULONG i;
	 bFound=FALSE;
	 p=(PUCHAR)NtOpenThread;;
	 i=0;
	 g_Thread_fnObOpenObjectByPointer=MyGetFunAddress(L"ObOpenObjectByPointer");

	 if(bFk)
	 {
		 ULONG bytes=0;
		 while(i<0x300)
		 {
			 if (*p==0x50 && 
				 *(p+1)==0xff &&
				 *(p+4)==0xff &&
				 *(p+7)==0xE8)
			 {
				 bFound=TRUE;
				 break;
			 }
			 i++;
			 p++;
		 }
		 if(!bFound)
		 {
			 KdPrint(("TP_DDK: 找不到 ObOpenObjectByPointer 函数地址\n"));
			 return;
		 }
		 g_Thread_HookObOpenObjectByPointer=p+1;


		 //保存旧的buffer
		 NtOpenThreadCodeLen=ade32_get_code_length(g_Thread_HookObOpenObjectByPointer,5);
		 RtlCopyMemory((PVOID)JmpNtOpenThread,(PVOID)g_Thread_HookObOpenObjectByPointer,NtOpenThreadCodeLen);

		 
		 //写入跳转 bytes=JmpNtOpenProcess-g_HookObOpenObjectByPointer-5;
		 bytes=(ULONG)JmpNtOpenThread-g_Thread_HookObOpenObjectByPointer-5;
		 DisableWP();
		 Irql=KeRaiseIrqlToDpcLevel();

		 *(PUCHAR)g_Thread_HookObOpenObjectByPointer=0xE9;
		 RtlCopyMemory((PVOID)(g_Thread_HookObOpenObjectByPointer+1),&bytes,sizeof(ULONG));

		 KeLowerIrql(Irql);
		 EnableWP();

		 KdPrint(("TP_DDK: 解除NtOpenThread保护!\n"));
	 }
	 else
	 {
		 if(*(PUCHAR)JmpNtOpenThread==0 || *(PUCHAR)JmpNtOpenThread == 0x90)
			 return;
		 DisableWP();
		 Irql=KeRaiseIrqlToDpcLevel();
		 RtlCopyMemory((PVOID)g_Thread_HookObOpenObjectByPointer,JmpNtOpenThread,NtOpenThreadCodeLen);
		 *(PUCHAR)JmpNtOpenThread=0;
		 KeLowerIrql(Irql);
		 EnableWP();

		 KdPrint(("TP_DDK: 还原NtOpenThread保护!\n"));
	 }


 }

 BOOLEAN  g_NtOpenThread_bIsDnfProcess=FALSE; //全局变量：是否是dnf进程
 __declspec(naked) void __stdcall JmpNtOpenThread()
 {
	 __asm
	 {
		 nop
			 nop
			 nop
			 nop
			 nop
			 nop
			 nop
			 nop
			 nop
			 nop
			 nop
			 nop
			 pushad
			 pushfd
			 call IsDnfProcess
			 mov g_NtOpenThread_bIsDnfProcess,al
			 popfd
			 popad
			 cmp g_NtOpenThread_bIsDnfProcess,0
			 je NotNDF
			 mov eax,g_Thread_HookObOpenObjectByPointer;
		 add eax,NtOpenThreadCodeLen;
		 jmp eax //DNF进程，执行TP的流程
NotNDF:	
		 mov eax,g_Thread_fnObOpenObjectByPointer
			 call eax //调用原生ObOpenObjectByPointer
			 mov edi, g_Thread_HookObOpenObjectByPointer
			 add edi,NtOpenThreadCodeLen
			 add edi,5
			 jmp edi	
	 }
 }



 void FkNtReadVirtualMemory( BOOLEAN bFk )
 {
	 KIRQL Irql;
	 PULONG pNtReadMemory;
	 pNtReadMemory=(PULONG)((ULONG)KeServiceDescriptorTable->ServiceTableBase+186*4);
	 //addrNtWriteMemory=(ULONG)KeServiceDescriptorTable->ServiceTableBase+277*4;

	 if(bFk)
	 {
		 //if ( *(PUCHAR)g_uNtReadVirtualMemoryAddr !=0x6A)
		 //{
			// KdPrint(("TP_DDK:SSDT表已经被hook,无法定位NtReadVirtualMemory\n"));
			// return;
		 //}

		 DisableWP();
		 Irql=KeRaiseIrqlToDpcLevel();
		 *pNtReadMemory=FakeNtReadVirtualMemory;
		 KeLowerIrql(Irql);
		 EnableWP();
		 KdPrint(("TP_DDK: 解除TP的NtReadVirtualMemory保护\n"));
	 }
	 else
	 {
		 DisableWP();
		 Irql=KeRaiseIrqlToDpcLevel();
		 *pNtReadMemory=g_uNtReadVirtualMemoryAddr;
		 KeLowerIrql(Irql);
		 EnableWP();
		 KdPrint(("TP_DDK: 恢复NtReadVirtualMemory SSDT表\n"));
	 }

 }


__declspec(naked)  void __stdcall FakeNtReadVirtualMemory()
 {
	 if(IsDnfProcess())
	 {
		 __asm
		 {
			 jmp [g_uNtReadVirtualMemoryAddr]
		 }
	 }
	 else
	 {
		 __asm
		 {
			 push 0x1C
			 push g_uNtReadVirtualMemoryAddr_offest3
			 mov eax,g_uNtReadVirtualMemoryAddr
			 add eax,7
			 jmp eax
		 }
	 }
 }


void FkNtWriteVirtualMemory( BOOLEAN bFk )
{
	KIRQL Irql;
	PULONG pNtWriteMemory;
	pNtWriteMemory=(PULONG)((ULONG)KeServiceDescriptorTable->ServiceTableBase+277*4);
	//addrNtWriteMemory=(ULONG)KeServiceDescriptorTable->ServiceTableBase+277*4;

	if(bFk)
	{
		//if ( *(PUCHAR)g_uNtReadVirtualMemoryAddr !=0x6A)
		//{
		// KdPrint(("TP_DDK:SSDT表已经被hook,无法定位NtReadVirtualMemory\n"));
		// return;
		//}

		DisableWP();
		Irql=KeRaiseIrqlToDpcLevel();
		*pNtWriteMemory=FakeNtWriteVirtualMemory;
		KeLowerIrql(Irql);
		EnableWP();

		KdPrint(("TP_DDK: 解除TP的NtWriteVirtualMemory保护\n"));
	}
	else
	{
		DisableWP();
		Irql=KeRaiseIrqlToDpcLevel();
		*pNtWriteMemory=g_uNtWriteVirtualMemoryAddr;
		KeLowerIrql(Irql);
		EnableWP();
		KdPrint(("TP_DDK: 恢复NtWriteVirtualMemory SSDT表\n"));
	}

}


__declspec(naked)  void __stdcall FakeNtWriteVirtualMemory()
{
	if(IsDnfProcess())
	{
		__asm
		{
			jmp [g_uNtWriteVirtualMemoryAddr]
		}
	}
	else
	{
		__asm
		{
			push 0x1C
				push g_uNtWriteVirtualMemoryAddr_offset3
				mov eax,g_uNtWriteVirtualMemoryAddr
				add eax,7
				jmp eax
		}
	}
}


void FkCRC( BOOLEAN bFk )
{
	KIRQL Irql;
	ULONG uImageBase,crc1,crc2,crc3=0;
	uImageBase=GetModuleBase("TesSafe.sys");
	if(uImageBase==0)
	{
		KdPrint(("TP_DDK:获取TesSafe模块失败,解除CRC失败\n"));
		return;
	}

	crc1=uImageBase+AddrCRC1;
	crc2=uImageBase+AddrCRC2;
	crc3=uImageBase+AddrCRC3;
	if(bFk)
	{
		//ULONG bytes_jmp=*(PULONG)(crc3+3);
		////bytes_jmp=g_uCRC3Ret-(crc3+2)-5
		//g_uCRC3Ret= bytes_jmp+(crc3+2)+5;
		//g_uDebugPort_Reset1=uImageBase+DebugPortReset1; //初始化清零函数1地址
		//g_uDebugPort_Reset1_4=*(PULONG)g_uDebugPort_Reset1; //保存清零函数1前四节
		//g_uDebugPort_Reset2=uImageBase+DebugPortReset2; //初始化清零函数2地址
		//g_uDebugPort_Reset2_4=*(PULONG)g_uDebugPort_Reset2; //保存清零函数2前四节
		
		DisableWP();
		Irql=KeRaiseIrqlToDpcLevel();

		//crc1
		*(PUCHAR)(crc1+0)=0x33;
		*(PUCHAR)(crc1+1)=0xC0;
		*(PUCHAR)(crc1+2)=0xC2;
		*(PUCHAR)(crc1+3)=0x0C;
		*(PUCHAR)(crc1+4)=0x00;

		//crc2
		*(PUCHAR)(crc2+0)=0xC3;
		KeLowerIrql(Irql);
		EnableWP();

		KdPrint(("TP_DDK:解除CRC1\n"));
		KdPrint(("TP_DDK:解除CRC2\n"));

		//CRC3
		WriteJmp((PVOID)crc3,FakeCRC3,JmpBackCRC3);

		KdPrint(("TP_DDK:解除CRC3\n"));
	}
	else
	{
		UnhookFunction((PVOID)crc3,JmpBackCRC3);
		KdPrint(("TP_DDK:恢复CRC3\n"));
	}
}

__declspec(naked) void __stdcall FakeCRC3()
{
	__asm
	{
		pushfd

		cmp edx,g_uDebugPort_Reset1
		je l_DebugPort_Reset1_4

		cmp edx,g_uDebugPort_Reset2
		je l_DebugPort_Reset2_4

		popfd
		push [edx]
		jmp [g_uCRC3Ret]


l_DebugPort_Reset1_4:
		popfd
		push [g_uDebugPort_Reset1_4]
		jmp [g_uCRC3Ret]

l_DebugPort_Reset2_4:
		popfd
		push [g_uDebugPort_Reset2_4]
		jmp [g_uCRC3Ret]

		


	}
}


void FkDebugReset( BOOLEAN bFk )
{
	KIRQL Irql;
	ULONG uImageBase,dbgPortCheck1,dbgPortPop;
	uImageBase=uImageBase=GetModuleBase("TesSafe.sys");
	if(uImageBase==0)
	{
		KdPrint(("TP_DDK:获取TesSafe模块失败,解除Debug清零失败\n"));
		return;
	}
	dbgPortCheck1=uImageBase+DebugPortCheck1;
	dbgPortPop=uImageBase+DebugPortPop;
	if (bFk)
	{
		DisableWP();
		Irql=KeRaiseIrqlToDpcLevel();

		*(PUCHAR)g_uDebugPort_Reset1=0xC3; //废除DebugPort清零函数1
		*(PUCHAR)g_uDebugPort_Reset2=0xC3; //废除DebugPort清零函数2

		KeLowerIrql(Irql);
		EnableWP();

		WriteJmp((PVOID)dbgPortCheck1,FakeDebugPortCheck,JmpBackDebugCheck); //跳过debugPort清零检测push
		WriteJmp((PVOID)dbgPortPop,FakeDebugPortPop,JmpBackDebugPop); //跳过debugPort清零pop


		KdPrint(("TP_DDK:解除DebugPort清零函数1\n"));
		KdPrint(("TP_DDK:解除DebugPort清零函数2\n"));
		KdPrint(("TP_DDK:解除DebugPort清零push函数1\n"));
		KdPrint(("TP_DDK:解除DebugPort清零pop函数\n"));
	}
	else
	{
		DisableWP();
		Irql=KeRaiseIrqlToDpcLevel();

		*(PULONG)g_uDebugPort_Reset1=g_uDebugPort_Reset1_4; //还原DebugPort清零函数1
		*(PULONG)g_uDebugPort_Reset2=g_uDebugPort_Reset2_4; //还原DebugPort清零函数2

		KeLowerIrql(Irql);
		EnableWP();
		UnhookFunction((PVOID)dbgPortCheck1,JmpBackDebugCheck);

		KdPrint(("TP_DDK:恢复DebugPort清零函数1\n"));
		KdPrint(("TP_DDK:恢复DebugPort清零函数2\n"));
		KdPrint(("TP_DDK:恢复DebugPort清零push函数1\n"));
		KdPrint(("TP_DDK:恢复DebugPort清零pop函数\n"));
	}
}

__declspec(naked) void __stdcall FakeDebugPort()
{
	__asm
	{
		pushfd

			cmp edx,g_uDebugPort_Reset1
			je l_DebugPort_Reset1_4

			cmp edx,g_uDebugPort_Reset2
			je l_DebugPort_Reset2_4

			popfd
			push [edx]
		jmp [g_uCRC3Ret]


l_DebugPort_Reset1_4:
		popfd
			push [g_uDebugPort_Reset1_4]
		jmp [g_uCRC3Ret]

l_DebugPort_Reset2_4:
		popfd
			push [g_uDebugPort_Reset2_4]
		jmp [g_uCRC3Ret]




	}
}

__declspec(naked) void __stdcall FakeDebugPortCheck()
{
	__asm
	{
		pushfd
		cmp edx,g_uDebugPort_Pointer
		je l_DebugPort_Pointer

		popfd
		push [edx]
		jmp [g_uDebugPortRet]

l_DebugPort_Pointer:
		popfd
		push 0
		jmp [g_uDebugPortRet]
	}
}

__declspec(naked) void __stdcall FakeDebugPortPop()
{
	__asm
	{
		pushfd
		cmp edx,g_uDebugPort_Pointer
		je l_DebugPort_Pointer

		popfd
		pop DWORD ptr [edx]
		jmp [g_uDebugPortPopRet]

l_DebugPort_Pointer:
		popfd
		add esp,0x4
		jmp [g_uDebugPortPopRet]
	}
}


 void __stdcall ZeroHardBreakPoint( PCONTEXT pContext,KPROCESSOR_MODE Mode )
{
	if(IsDnfProcess())
	{
		__try
		{
			if(Mode!=KernelMode)
			{
				ProbeForWrite(pContext,sizeof(CONTEXT),sizeof(UCHAR));
				pContext->Dr0=0;
				pContext->Dr1=0;
				pContext->Dr2=0;
				pContext->Dr3=0;
				pContext->Dr6=0;
				pContext->Dr7=0;
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}
	}
}

 __declspec(naked) void _stdcall FakeNtGetContextThread()
 {
	 __asm
	 {
		 pushad
		 pushfd
		 push [ebp-0x4]
		 push [ebp+0xC]
		 call ZeroHardBreakPoint
		 popfd
		 popad
		 mov eax,esi
		 pop esi
		 mov esp,ebp
		 pop ebp
		 retn 0x8
	 }
 }

 void FkHardBreakPoint( BOOLEAN bFk )
 {
	 __asm int 3
	 if(bFk)
	 {
		 BOOLEAN bFound=FALSE;
		 ULONG i;
		 ULONG p=g_uNtGetContextThreadAddr;
		 for(i=0;i<0x100;i++)
		 {
			 if(*(PUCHAR)(p+0)==0x8B &&
				*(PUCHAR)(p+1)==0xC6 &&
				*(PUCHAR)(p+2)==0x5E &&
				*(PUCHAR)(p+3)==0xC9)
			 {
				 bFound=TRUE;
				 g_uNtGetContextThreadInjectAddr=p;
				 break;
			 }
			 p++;
		 }
		 if(!bFound)
		 {
			 KdPrint(("TP_DDK: 找不到NtGetContextThreadInjectAddr \n"));
			 return;
		 }

		 WriteJmp((PVOID)g_uNtGetContextThreadInjectAddr,FakeNtGetContextThread,JmpBackNtGetContextThread);
	 }
	 else
	 {
		 if(g_uNtGetContextThreadInjectAddr==0)
			 return;
		 UnhookFunction((PVOID)g_uNtGetContextThreadInjectAddr,JmpBackNtGetContextThread);
	 }
 }

