from unicorn import *
from unicorn.x86_const import *
from loguru import logger
from pathlib import Path
from typing import Dict, Tuple
from pwn import p32

def read(f : Path) -> bytes:
    with open(f, "rb") as file:
        return file.read()

# NOTE: pay attention to UC_MODE
mu = Uc (UC_ARCH_X86, UC_MODE_32)

BASE_ADDR  = 0x08048000
BASE_SIZE  = 0x300000 # .bss .data .txt all load in
STACK_ADDR = 0x0
STACK_SIZE = 0x100000

mu.mem_map(BASE_ADDR, BASE_SIZE)
mu.mem_map(STACK_ADDR, STACK_SIZE)

mu.mem_write(BASE_ADDR ,read("./function"))
mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE // 2)


super_func = 0x0000057B 
batman     = 0x00000660


def hook_code(uc : Uc, addr, size, data):
    # logger.info(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(addr, size))
    if addr == 0x5CA + BASE_ADDR:
        print('[!] HIT')
        # uc.reg_write(UC_X86_REG_EIP, BASE_ADDR + super_func)
        esp = uc.reg_read(UC_X86_REG_ESP)
        uc.mem_write(esp, p32(5))
        uc.mem_write(esp + 4, p32(BASE_ADDR + batman))
    
    # if addr == 0x57B + BASE_ADDR or addr == addr == 0x5CA + BASE_ADDR:
    #     print(f"at {hex(addr)}")
    #     esp = uc.reg_read(UC_X86_REG_ESP)
    #     [print(repr(bytes(uc.mem_read(esp + i * 4, 4)))) for i in range(6)]
        
    # superfunction return
    if addr == 0x5B1 + BASE_ADDR:
        eax = uc.reg_read(UC_X86_REG_EAX)
        print(f"[I] eax is {int(eax)}")
        
# tracing all instructions with customized callback
# add here for debugging
mu.hook_add(UC_HOOK_CODE, hook_code)

mu.emu_start(BASE_ADDR + 0x5B4, BASE_ADDR + 0x5D5)
# print("")








