#include "Inline_Hook_NtOpenProcess.h"


ULONG OrgNtOpenProcess;

void Inline_Hook_NtOpenProcess()
{
	KIRQL Irql;
	ULONG JMP;
	OrgNtOpenProcess=MyGetFunAddress(L"NtOpenProcess");
	JMP=(ULONG)MyNtOpenProcess-OrgNtOpenProcess-5;

	__asm //去掉页面保护
	{
		cli
			mov eax,cr0
			and eax,not 10000h //and eax,0FFFEFFFFh
			mov cr0,eax
	}

	//提升IRQL中断级
	Irql=KeRaiseIrqlToDpcLevel();
	
	*(char*)OrgNtOpenProcess=0xE9;
	*(ULONG*)((ULONG)OrgNtOpenProcess+1)=JMP;
	
	//恢复Irql
	KeLowerIrql(Irql);
	__asm  //恢复页面保护
	{ 
		mov eax,cr0
			or eax,10000h
			mov cr0,eax
			sti
	}
}

NTSTATUS MyNtOpenProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	)
{
	
	//__asm int 3
	if(ClientId!=NULL  && Inline_NtOpenProcess_Id!=NULL)
	{
		NTSTATUS rc;
		HANDLE PID;
		PID=ClientId->UniqueProcess;
		if(PID==Inline_NtOpenProcess_Id)
		{
			KdPrint(("+++第三方程序：%s 企图打开目标进程+++\n",(PTSTR)((ULONG)PsGetCurrentProcess()+0x174)));
			ProcessHandle=NULL;
			rc=STATUS_ACCESS_DENIED;
			__asm
			{
				mov esp,ebp
				pop ebp
				retn 0x10
			}
		}
	}


	__asm
	{
		mov esp,ebp
		pop ebp

		push   0C4h
		mov eax,OrgNtOpenProcess
		add eax,5
		jmp eax
	}


}


void Inline_unHook_NtOpenProcess()
{
	KIRQL Irql;
	ULONG JMP;
	OrgNtOpenProcess=MyGetFunAddress(L"NtOpenProcess");
	JMP=(ULONG)MyNtOpenProcess-OrgNtOpenProcess-5;

	__asm //去掉页面保护
	{
		cli
			mov eax,cr0
			and eax,not 10000h //and eax,0FFFEFFFFh
			mov cr0,eax
	}

	//提升IRQL中断级
	Irql=KeRaiseIrqlToDpcLevel();

	*(char*)OrgNtOpenProcess=0x68;
	*(ULONG*)((ULONG)OrgNtOpenProcess+1)=0xC4;

	//恢复Irql
	KeLowerIrql(Irql);
	__asm  //恢复页面保护
	{ 
		mov eax,cr0
			or eax,10000h
			mov cr0,eax
			sti
	}
}