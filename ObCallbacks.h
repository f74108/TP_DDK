#pragma once
#include "ntddk.h"

NTSTATUS register_process_register_protect(PDRIVER_OBJECT pdriverobj);//注册进程，注册表 保护回调
