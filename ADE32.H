#pragma once

//返回opcode0指向的指令的长度
ULONG ade32_disasm(IN PVOID opcode0);

//返回值 >= length 并且按照指令对齐
//opcode 指令开端
//length 长度
ULONG ade32_get_code_length(PVOID opcode, ULONG length);