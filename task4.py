from unicorn import *
from unicorn.arm_const import *
from loguru import logger
from pathlib import Path
from typing import Dict, Tuple
from pwn import p32

def read(f : Path) -> bytes:
    with open(f, "rb") as file:
        return file.read()

# NOTE: pay attention to UC_MODE
mu = Uc (UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)

BASE_ADDR  = 0x010000 # can found in IDA
BASE_SIZE  = 0x300000 # .bss .data .txt all load in
STACK_ADDR = 0x400000
STACK_SIZE = 0x100000

mu.mem_map(BASE_ADDR, BASE_SIZE)
mu.mem_map(STACK_ADDR, STACK_SIZE)

mu.mem_write(BASE_ADDR ,read("./task4"))
mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE // 2)


CCC_ENTRY = 0x000104D0
CCC_END = 0x00010580 # .text:00010580                 BX      LR

'''
The first argument of function is passed in R0 (UC_ARM_REG_R0).
Return value is also put in R0
The second argument is passed in R1 (UC_ARM_REG_R1).
You can get unicorn instance for this architecture this way: mu = Uc (UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
'''

stack = []
cache = {} # arg0 -> return value

def hook_code(uc : Uc, addr, size, data):
    # logger.info(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(addr, size))
    if addr == CCC_ENTRY:
        r0 = uc.reg_read(UC_ARM_REG_R0)

        if r0 in cache:
            # print(f"[D] cache hit with r0[{r0}]")
            ret = cache[r0]
            uc.reg_write(UC_ARM_REG_R0,  ret)
            # 0x000105BC is `BX LR`
            uc.reg_write(UC_ARM_REG_PC, 0x000105BC) # avoid conflict with following CCC_END

        else:
            stack.append(r0)

        
    # superfunction return
    if addr == CCC_END:
        ret = uc.reg_read(UC_ARM_REG_R0)
        r0 = stack.pop()
        cache[r0] = ret
        
# tracing all instructions with customized callback
mu.hook_add(UC_HOOK_CODE, hook_code)

mu.emu_start(0x0010584, 0x00105A8)
# stop in printf
r0 = mu.reg_read(UC_ARM_REG_R0)
string = bytes(mu.mem_read(r0, 0x20)).split(b'\x00')[0]
print(string)
r1 = mu.reg_read(UC_ARM_REG_R1)
print(r1)








