from unicorn import *
from unicorn.x86_const import *
import sys
shellcode = b"\xe8\xff\xff\xff\xff\xc0\x5d\x6a\x05\x5b\x29\xdd\x83\xc5\x4e\x89\xe9\x6a\x02\x03\x0c\x24\x5b\x31\xd2\x66\xba\x12\x00\x8b\x39\xc1\xe7\x10\xc1\xef\x10\x81\xe9\xfe\xff\xff\xff\x8b\x45\x00\xc1\xe0\x10\xc1\xe8\x10\x89\xc3\x09\xfb\x21\xf8\xf7\xd0\x21\xd8\x66\x89\x45\x00\x83\xc5\x02\x4a\x85\xd2\x0f\x85\xcf\xff\xff\xff\xec\x37\x75\x5d\x7a\x05\x28\xed\x24\xed\x24\xed\x0b\x88\x7f\xeb\x50\x98\x38\xf9\x5c\x96\x2b\x96\x70\xfe\xc6\xff\xc6\xff\x9f\x32\x1f\x58\x1e\x00\xd3\x80" 


BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024 * 1024

mu = Uc (UC_ARCH_X86, UC_MODE_32)

mu.mem_map(BASE, 1024 * 1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)


mu.mem_write(BASE, shellcode)
mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE // 2)

def syscall_num_to_name(num):
    syscalls = {
        1 : "sys_exit", 
        15: "sys_chmod"
    }
    return syscalls[num]

# ref: https://defuse.ca/online-x86-assembler.htm#disassembly
int_0x80 = b"\xCD\x80"
def hook_code(mu : Uc, addr, size, user_data):
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(addr, size))  
    
    inst : bytearray = mu.mem_read(addr ,size)
    
    if inst == int_0x80:
        eax = mu.reg_read(UC_X86_REG_EAX)
        ebx = mu.reg_read(UC_X86_REG_EBX)
        ecx = mu.reg_read(UC_X86_REG_ECX)

        sysc_name = syscall_num_to_name(eax)

        if sysc_name == "sys_chmod" :
            # int chmod(const char *pathname, mode_t mode);
            path = mu.mem_read(ebx, 0x20).split(b'\x00')[0]
            print(f"[+] syscall {sysc_name} ({path.decode()}, {oct(ecx)})")

        if sysc_name == "sys_exit":
            print(f"[+] exit({ebx})")
            sys.exit()

        # all call instruction must calibrate rip
        mu.reg_write(UC_X86_REG_EIP, addr + size)
    

mu.hook_add(UC_HOOK_CODE, hook_code)
mu.emu_start(BASE, BASE + len(shellcode))