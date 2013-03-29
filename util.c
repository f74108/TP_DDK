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
	SSDT_NtOpenProcess_Cur_Addr=(PULONG)SSDT_NtOpenProcess_Cur_Addr;
	return SSDT_NtOpenProcess_Cur_Addr;
}

#pragma  PAGECODE
ULONG GetOrgSSdtFuncRVA(ULONG index,PLOADED_KERNEL_INFO plki)
{
	ULONG rva,newServiceTableBase;
	if(plki==NULL)
		return NULL;
	rva=(ULONG)KeServiceDescriptorTable->ServiceTableBase-(ULONG)plki->OriginalKernelBase;
	newServiceTableBase=(ULONG)plki->NewKernelBase+rva;
	rva=*(PULONG)(newServiceTableBase+4*index)-LoadBase;
	
	return rva;
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
	__asm int 3
	length = ade32_get_code_length(Function, 5);
	if(length == 0)
		return FALSE;
	
	temp = (PUCHAR)Function + length;
	RtlCopyMemory((PVOID)JmpBuffer, Function, length);

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


//PVOID MiFindExportedRoutineByName (IN PVOID DllBase,IN PANSI_STRING AnsiImageRoutineName)
//{
//	USHORT OrdinalNumber;
//	PULONG NameTableBase;
//	PUSHORT NameOrdinalTableBase;
//	PULONG Addr;
//	LONG High;
//	LONG Low;
//	LONG Middle;
//	LONG Result;
//	ULONG ExportSize;   // 保存表项的大小
//	PVOID FunctionAddress;
//	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
//	PAGED_CODE();
//	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData (
//		DllBase,
//		TRUE,
//		IMAGE_DIRECTORY_ENTRY_EXPORT,
//		&ExportSize);
//	if (ExportDirectory == NULL) {
//		return NULL;
//	}
//	NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);
//	NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
//	//二分查找法
//	Low = 0;
//	Middle = 0;
//	High = ExportDirectory->NumberOfNames - 1;
//	while (High >= Low) {
//		Middle = (Low + High) >> 1;
//		Result = strcmp (AnsiImageRoutineName->Buffer,
//			(PCHAR)DllBase + NameTableBase[Middle]);
//		if (Result < 0) {
//			High = Middle - 1;
//		}
//		else if (Result > 0) {
//			Low = Middle + 1;
//		}
//		else {
//			break;
//		}
//	}
//	// 如果High < Low，表明没有在EAT中找到这个函数；否则，返回此函数的索引
//	if (High < Low) {
//		return NULL;
//	}
//	OrdinalNumber = NameOrdinalTableBase[Middle];
//	// 如果索引值大于EAT中已有的函数数量，则查找失败
//	if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
//		return NULL;
//	}
//	Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);
//	FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);
//	ASSERT ((FunctionAddress <= (PVOID)ExportDirectory) ||
//		(FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));
//	return FunctionAddress;
//}

ULONG GetOriginalKernelBase()
{
	//ANSI_STRING funcName;
	//PVOID func;
	//ULONG rva;
	//RtlInitAnsiString(&funcName,"NtOpenProcess");
	//func=MiFindExportedRoutineByName(newKernelBase,&funcName);
	//rva=(ULONG)func-newKernelBase;
	//return (ULONG)NtOpenProcess-rva;
	if(isPaeOpened())
		return GetModuleBase("ntkrnlpa.exe");
	else
		return GetModuleBase("ntoskrnl.exe");

}

BOOLEAN  IsDnfProcess()
{
	PEPROCESS curProcess= PsGetCurrentProcess();
	PUCHAR pszCurName=PsGetProcessImageFileName(curProcess);
	if(_stricmp("dnf.exe",pszCurName)==0 ||
		_stricmp("DNFchina.exe",pszCurName)==0)
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
		KdPrint(("PID:%d, process name:%S pInfo:%x \n", pInfo->ProcessId, pszProcessName,pInfo)); 

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


DWORD GetPlantformDependentInfo ( DWORD dwFlag )   
{    
	DWORD current_build;    
	DWORD ans = 0;    

	PsGetVersion(NULL, NULL, &current_build, NULL);    

	switch ( dwFlag )   
	{    
	case EPROCESS_SIZE:    
		if (current_build == BuildWin2000) ans = 0 ;        // 2000，当前不支持2000，下同   -------------------这里的这些参数应该怎么得到。没有头绪。。。
		if (current_build == BuildXp3) ans = 0x25C;     // xp   
		if (current_build == BuildWin2003) ans = 0x270;     // 2003   
		if (current_build == BuildWin7) ans=7777;		//win7 未定
		break;    
	case PEB_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x1b0;    
		if (current_build == 3790)  ans = 0x1a0;   
		break;    
	case FILE_NAME_OFFSET:    
		if (current_build == BuildWin2000)  ans = 0;    
		if (current_build == BuildXp3)  ans = 0x174;    
		if (current_build == BuildWin2003)  ans = 0x164;   
		break;    
	case PROCESS_LINK_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x088;    
		if (current_build == 3790)  ans = 0x098;   
		break;    
	case PROCESS_ID_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x084;    
		if (current_build == 3790)  ans = 0x094;   
		break;    
	case EXIT_TIME_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x078;    
		if (current_build == 3790)  ans = 0x088;   
		break;
	case DebugPort_OFFSET:
		if(current_build==BuildXp3) ans=0xBC;
		if(current_build==BuildWin2003) ans=0xCC;
		if(current_build==BuildWin7) ans=0x0ec;
		break;
	case PROCESS_ObjectTable_OFFSET:
		if(current_build==BuildXp3) ans=0xC4;
		if(current_build==BuildWin2003) ans=0xD4;
		if(current_build==BuildWin7) ans=0x0f4;
		break;
	}    
	return ans;    
}

void EnumProcessList ()   
{   
	PROCESS_INFO    ProcessInfo = {0} ;   
	DWORD       EProcess ;   
	DWORD       FirstEProcess ;   
	DWORD           dwCount = 0 ;   
	LIST_ENTRY*     ActiveProcessLinks ;   

	DWORD   dwPidOffset     = GetPlantformDependentInfo ( PROCESS_ID_OFFSET ) ;   
	DWORD   dwPNameOffset   = GetPlantformDependentInfo ( FILE_NAME_OFFSET ) ;   
	DWORD   dwPLinkOffset   = GetPlantformDependentInfo ( PROCESS_LINK_OFFSET ) ;  
	DWORD	dwDebugPortOffset=GetPlantformDependentInfo(DebugPort_OFFSET);

	DbgPrint ( "PidOff=0x%X NameOff=0x%X LinkOff=0x%X DebugPortOff:0x%X \n",
		dwPidOffset, dwPNameOffset, dwPLinkOffset,dwDebugPortOffset ) ;   

	FirstEProcess = EProcess = (DWORD)PsGetCurrentProcess () ;   

	__try {   
		while ( EProcess != 0)   
		{   
			dwCount ++ ;   

			ProcessInfo.dwProcessId = *( (DWORD*)( EProcess + dwPidOffset ) );   
			ProcessInfo.pImageFileName = (PUCHAR)( EProcess + dwPNameOffset ) ;   

			DbgPrint ( "[Pid=%8d] EProcess=0x%08X %s\n", ProcessInfo.dwProcessId, EProcess, ProcessInfo.pImageFileName ) ;   

			ActiveProcessLinks = (LIST_ENTRY*) ( EProcess + dwPLinkOffset ) ;   
			EProcess = (DWORD)ActiveProcessLinks->Flink - dwPLinkOffset ;    

			if ( EProcess == FirstEProcess )   
				break ;   
		}   
		DbgPrint ( "ProcessNum = %d\n", dwCount ) ;   
	} __except ( 1 ) {   
		DbgPrint ( "EnumProcessList exception !" ) ;   
	}   
} 

ULONG GetProcessByName( PUCHAR pName )
{
	PROCESS_INFO    ProcessInfo = {0} ;   
	DWORD       EProcess ;   
	DWORD       FirstEProcess ;   
	DWORD       dwCount = 0 ;   
	LIST_ENTRY*     ActiveProcessLinks ;   
	DWORD	ObjectTable=0;

	DWORD   dwPidOffset     = GetPlantformDependentInfo ( PROCESS_ID_OFFSET ) ;   
	DWORD   dwPNameOffset   = GetPlantformDependentInfo ( FILE_NAME_OFFSET ) ;   
	DWORD   dwPLinkOffset   = GetPlantformDependentInfo ( PROCESS_LINK_OFFSET ) ;  
	DWORD	dwDebugPortOffset=GetPlantformDependentInfo(DebugPort_OFFSET);
	DWORD	dwObjectTable	=GetPlantformDependentInfo(PROCESS_ObjectTable_OFFSET);

	if(pName==NULL)
		return 0;
	FirstEProcess = EProcess = (DWORD)PsGetCurrentProcess () ;   

	__try {   
		while ( EProcess != 0)   
		{   
			dwCount ++ ;   

			ProcessInfo.dwProcessId = *( (DWORD*)( EProcess + dwPidOffset ) );   
			ProcessInfo.pImageFileName = (PUCHAR)( EProcess + dwPNameOffset );
			ObjectTable=*(PULONG)(EProcess+dwObjectTable);
			if(_stricmp(ProcessInfo.pImageFileName,pName)==0 &&
				ObjectTable!=NULL)
			{
				return EProcess;
			}

			ActiveProcessLinks = (LIST_ENTRY*) ( EProcess + dwPLinkOffset ) ;   
			EProcess = (DWORD)ActiveProcessLinks->Flink - dwPLinkOffset ;    
			if ( EProcess == FirstEProcess )   
				break ;   
		}    
	} __except ( 1 ) {   
		DbgPrint ( "EnumProcessList exception !" ) ;   
	}   

	return 0;
}



_QuerySystemInformation NtQuerySystemInforamtion;
NTSTATUS GetModuleInfo(char* chModName,PSYSTEM_MODULE_INFORMATION	psmi)
{
	NTSTATUS					st;
	SYSTEM_MODULE_INFORMATION*			plmi;
	ULONG						ulInfoLen;
	ULONG						i;
	char*						s;
	ULONG						ulOffet;
	UNICODE_STRING				usFuncName;


	KdPrint(("DEBUG: calling GetModuleInfo \n"));
	CHECK_IRQL

		//verify params
		if (psmi == NULL || chModName==NULL)
		{
			return STATUS_UNSUCCESSFUL;
		}

		//try to get address of NtQuerySystemInformation
		if (NULL == NtQuerySystemInforamtion)
		{

			RtlInitUnicodeString ( &usFuncName, L"NtQuerySystemInformation");
			NtQuerySystemInforamtion = (_QuerySystemInformation)MmGetSystemRoutineAddress (&usFuncName);

			if (!NtQuerySystemInforamtion)
			{
				KdPrint(("cannot get NtQuerySystemInformation \n"));
				return STATUS_UNSUCCESSFUL;
			}
		}

		st = NtQuerySystemInforamtion( SystemModuleInformation,
			NULL,
			0,
			&ulInfoLen);
		if (!ulInfoLen)
		{
			return STATUS_UNSUCCESSFUL;
		}

		plmi = (SYSTEM_MODULE_INFORMATION*)ExAllocatePool (NonPagedPool, ulInfoLen+sizeof(ULONG));

		if (plmi->Modules == NULL)
		{
			return STATUS_UNSUCCESSFUL;
		}

		st = NtQuerySystemInforamtion(SystemModuleInformation,
			(PVOID)plmi,
			ulInfoLen,
			&ulInfoLen);
		if (!NT_SUCCESS(st))
		{
			KdPrint(("Query info of modules failed 0x%X \n",st));
			return st;
		}
		//find to module we want
		for (i=0 ; i< plmi->ModulesCount ; i++)
		{
			s=plmi->Modules[i].Name;
			ulOffet = plmi->Modules->NameOffset;
			if (strcmp (_strupr (&s[ulOffet]),_strupr (chModName))==0)
			{
				_try
				{
					RtlCopyMemory( psmi,&(plmi->Modules[i]),sizeof(SYSTEM_MODULE));
				}
				_except(EXCEPTION_EXECUTE_HANDLER)
				{
					ExFreePool(plmi);
					return GetExceptionCode();
				}
				KdPrint(("Path: %s \n Base:0x%X \n Size:0x%X \n",
					psmi->Modules->Name,plmi->Modules->ImageBaseAddress,plmi->Modules->ImageSize));
				ExFreePool(plmi);
				return STATUS_SUCCESS;
			}

		}
		ExFreePool(plmi);
		return STATUS_UNSUCCESSFUL;
}


NTSTATUS LoadKernelFile(OUT PLOADED_KERNEL_INFO plki )
{
	NTSTATUS st;
	SYSTEM_MODULE_INFORMATION smi;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING ObjectName;
	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_STANDARD_INFORMATION FileInformation;
	PVOID pFileBuffer;
	ULONG uFileLength;

	PIMAGE_NT_HEADERS pImageNTHeaders;
	PVOID pImageBase;
	ULONG uImageSize;
	PSYSTEM_DESCRIPTOR_TABLE NewPsdt;
	PWCH pszFullFileName=NULL;


	if (plki == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(plki,sizeof(LOADED_KERNEL_INFO));

	pszFullFileName=L"\\SystemRoot\\system32\\ntkrnlpa.exe";

	if (GetModuleBase("ntkrnlpa.exe")==0)
	{
		pszFullFileName=L"\\SystemRoot\\system32\\ntoskrnl.exe";
		if (GetModuleBase("ntoskrnl.exe")==0)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}


	RtlZeroMemory(&ObjectAttributes,sizeof(POBJECT_ATTRIBUTES));
	RtlInitUnicodeString(&ObjectName,pszFullFileName);
	InitializeObjectAttributes(&ObjectAttributes,
								&ObjectName,
								OBJ_CASE_INSENSITIVE,
								NULL,NULL);
	st=ZwCreateFile(&FileHandle,
				  GENERIC_READ,
				  &ObjectAttributes,
				  &IoStatusBlock,
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ,
					FILE_OPEN,
					FILE_SYNCHRONOUS_IO_NONALERT,
					NULL,NULL);
	if(!NT_SUCCESS(st))
	{
		KdPrint(("ZwCreateFile Failed!\n"));
		return st;
	}

	RtlZeroMemory(&FileInformation,sizeof(FILE_STANDARD_INFORMATION));
	st=ZwQueryInformationFile(FileHandle,
						   &IoStatusBlock,
						   &FileInformation,
							sizeof(FILE_STANDARD_INFORMATION),
							FileStandardInformation);
	if(!NT_SUCCESS(st))
	{
		KdPrint(("ZwQueryInformationFile Failed!\n"));
		if(FileHandle!=NULL)
			ZwClose(FileHandle);
		return st;
	}

	uFileLength=(ULONG)(FileInformation.EndOfFile.QuadPart);
	pFileBuffer=ExAllocatePool(NonPagedPool,uFileLength);
	if(pFileBuffer==NULL)
	{
		KdPrint(("STATUS_MEMORY_NOT_ALLOCATED !\n"));
		if(FileHandle!=NULL)
			ZwClose(FileHandle);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	st=ZwReadFile(FileHandle,NULL,NULL,NULL,&IoStatusBlock,pFileBuffer,uFileLength,NULL,NULL);
	if(!NT_SUCCESS(st))
	{
		KdPrint(("ZwReadFile Failed! %x\n",st));
		if(FileHandle!=NULL)
			ZwClose(FileHandle);
		if(pFileBuffer!=NULL)
			ExFreePool(pFileBuffer);
		return st;
	}


	if( ((PIMAGE_DOS_HEADER)pFileBuffer)->e_magic!= IMAGE_DOS_SIGNATURE )
	{
		if(FileHandle!=NULL)
			ZwClose(FileHandle);
		if(pFileBuffer!=NULL)
			ExFreePool(pFileBuffer);
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	pImageNTHeaders=RtlImageNtHeader(pFileBuffer);
	if(pImageNTHeaders==NULL)
	{
		if(FileHandle!=NULL)
			ZwClose(FileHandle);
		if(pFileBuffer!=NULL)
			ExFreePool(pFileBuffer);
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	if(!ImageFile(pFileBuffer,&pImageBase))
	{
		KdPrint(("ImageFile failed\n"));
		if(FileHandle!=NULL)
			ZwClose(FileHandle);
		if(pFileBuffer!=NULL)
			ExFreePool(pFileBuffer);
		return STATUS_UNSUCCESSFUL;
	}



	if(FileHandle!=NULL)
		ZwClose(FileHandle);
	if(pFileBuffer!=NULL)
		ExFreePool(pFileBuffer);

	plki->OriginalKernelBase=GetOriginalKernelBase();
	plki->NewKernelBase=pImageBase;
	
	return STATUS_SUCCESS;
}

UINT AlignSize(UINT nSize, UINT nAlign)
{
	return ((nSize + nAlign - 1) / nAlign * nAlign);
}

BOOL ImageFile(PBYTE pFileBuffer,BYTE **ImageModuleBase )
{
	PIMAGE_DOS_HEADER ImageDosHeader;
	PIMAGE_NT_HEADERS ImageNtHeaders;
	PIMAGE_SECTION_HEADER ImageSectionHeader;
	DWORD FileAlignment,SectionAlignment,NumberOfSections,SizeOfImage,SizeOfHeaders;
	DWORD Index;
	BYTE *ImageBase;
	DWORD SizeOfNtHeaders;
	ImageDosHeader=(PIMAGE_DOS_HEADER)pFileBuffer;

	if (ImageDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
		return FALSE;

	ImageNtHeaders=(PIMAGE_NT_HEADERS)(pFileBuffer+ImageDosHeader->e_lfanew);

	if(ImageNtHeaders->Signature!=IMAGE_NT_SIGNATURE)
		return FALSE;

	FileAlignment=ImageNtHeaders->OptionalHeader.FileAlignment;
	SectionAlignment=ImageNtHeaders->OptionalHeader.SectionAlignment;
	NumberOfSections=ImageNtHeaders->FileHeader.NumberOfSections;
	SizeOfImage=ImageNtHeaders->OptionalHeader.SizeOfImage;
	SizeOfHeaders=ImageNtHeaders->OptionalHeader.SizeOfHeaders;
	SizeOfImage=ImageNtHeaders->OptionalHeader.SizeOfImage;

	ImageBase=ExAllocatePool(NonPagedPool,SizeOfImage);
	if(ImageBase==NULL)
		return FALSE;

	RtlZeroMemory(ImageBase,SizeOfImage);
	SizeOfNtHeaders=sizeof(ImageNtHeaders->FileHeader)+
						sizeof(ImageNtHeaders->Signature)+
						ImageNtHeaders->FileHeader.SizeOfOptionalHeader;
	ImageSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)ImageNtHeaders+SizeOfNtHeaders);
	for(Index=0;Index<NumberOfSections;Index++)
	{
		ImageSectionHeader[Index].SizeOfRawData=AlignSize(ImageSectionHeader[Index].SizeOfRawData,FileAlignment);
		ImageSectionHeader[Index].Misc.VirtualSize=AlignSize(ImageSectionHeader[Index].Misc.VirtualSize,SectionAlignment);
	}

	if (ImageSectionHeader[NumberOfSections-1].VirtualAddress+ImageSectionHeader[NumberOfSections-1].SizeOfRawData>SizeOfImage)
	{
		ImageSectionHeader[NumberOfSections-1].SizeOfRawData = SizeOfImage-ImageSectionHeader[NumberOfSections-1].VirtualAddress;
	}
	RtlCopyMemory(ImageBase,pFileBuffer,SizeOfHeaders);

	for (Index=0;Index<NumberOfSections;Index++)
	{
		DWORD FileOffset=ImageSectionHeader[Index].PointerToRawData;
		DWORD Length=ImageSectionHeader[Index].SizeOfRawData;
		DWORD ImageOffset=ImageSectionHeader[Index].VirtualAddress;
		RtlCopyMemory(&ImageBase[ImageOffset],&pFileBuffer[FileOffset],Length);
	}

	*ImageModuleBase=ImageBase;

	return TRUE;
}

BOOLEAN isPaeOpened()
{
	ULONG uCr4=0;
	__asm
	{
		_emit 0x0F
		_emit 0x20
		_emit 0xE0
		mov uCr4,eax
	}
	return (uCr4 & 0x20)==0x20;

}


