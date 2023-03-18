from unicorn import *
from unicorn.x86_const import *
from loguru import logger
from pathlib import Path
from typing import Dict, Tuple

def read(f : Path) -> bytes:
    with open(f, "rb") as file:
        return file.read()

# initialize Unicorn engine
# first - main architecture branch. The constant starts with UC_ARCH_
# second - further architecture specification. The constant starts with UC_MODE_
mu = Uc (UC_ARCH_X86, UC_MODE_64)

BASE_ADDR  = 0x400000
BASE_SIZE  = 0x300000 # .bss .data .txt all load in
STACK_ADDR = 0x0
STACK_SIZE = 0x100000

mu.mem_map(BASE_ADDR, BASE_SIZE)
mu.mem_map(STACK_ADDR, STACK_SIZE)

mu.mem_write(BASE_ADDR ,read("./fibonacci"))
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1)

main_start = 0x4004E0
main_end   = 0x400582

skip_instructions = [
    0x4004F6, #                 call    _setbuf
    0x400502, #                 call    _printf
    0x400575, #                 call    __IO_putc
]

__flag_putc      = 0x400560
fibonacci_entry  = 0x400670
fibonacci_ends   = [0x4006F1, 0x400709]
ret_of_fibonacci = fibonacci_ends[1]
stack = []
cache : Dict[Tuple[int, int], Tuple[int, bytes]] = {}

def hook_code(uc : Uc, addr, size, data):
    # logger.info(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(addr, size))
    if addr in skip_instructions:
        uc.reg_write(UC_X86_REG_RIP, addr + size)
    
    if addr == __flag_putc:
        c = uc.reg_read(UC_X86_REG_RDI) 
        print(chr(int(c & 0xff)), end = "")
        # print(chr(c), end = "")
        uc.reg_write(UC_X86_REG_RIP, addr + size)
    
    if addr == fibonacci_entry:
        # logger.info("HIT fibonacci_entry")
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        res = bytes(uc.mem_read(rsi, 8))
        stack.append((rdi, rsi, res))

        if (rdi, res) in cache:
            (rax, res) = cache[(rdi, res)]
            uc.reg_write(UC_X86_REG_RAX, rax)
            uc.mem_write(rsi, res)
            uc.reg_write(UC_X86_REG_RIP, ret_of_fibonacci)
        
    elif addr in fibonacci_ends:
        # logger.info("HIT fibonacci_ends")
        rax : int = uc.reg_read(UC_X86_REG_RAX)
        rdi, rsi, res = stack.pop()

        new_res = bytes(uc.mem_read(rsi, 8))

        cache[(rdi, res)] = (rax, new_res)
        # logger.info(f"N = {rdi} {res} cached")
        
# tracing all instructions with customized callback
# add here for debugging
mu.hook_add(UC_HOOK_CODE, hook_code)

mu.emu_start(main_start, main_end)
print("")








