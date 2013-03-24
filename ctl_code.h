#ifndef   CTL_CODE
#pragma message("\n \n-----------EXE模式 Include winioctl.h ")
#include<winioctl.h> //CTL_CODE ntddk.h wdm.h
#else 
#pragma message("-\n \n---------SYS模式NO Include winioctl.h ")
#endif

#define TEST_1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define SSDT_NtOpenProcess_Hook_Code CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define Inline_NtOpenProcess_Hook_Code CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define TP_DDK_Enable_Code CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_IN_DIRECT,FILE_ANY_ACCESS)