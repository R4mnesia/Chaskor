from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *

def elf_loader32(file):
    print("ELF 32 bits loader")

# CS_OP_IMM = immediate operands

def elf_loader64(file):

    print("ELF 64 bits loader")
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name('.text')
        code = text.data()
        addr = text['sh_addr']

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for instr in md.disasm(code, addr):

        if instr.mnemonic == "xor":
            op1, op2 = instr.operands

            if op1.type == CS_OP_REG and op2.type == CS_OP_REG: # xor ecx, ecx
                if op1.reg == op2.reg:
                    print(f"[ZERO]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
                elif op1.reg != op2.reg:
                    print(f"[MIX REG]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

            elif op1.type == CS_OP_REG and op2.type == CS_OP_IMM: # xor ecx, 0x33
                print(f"[KEY]:  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
            
            elif op1.type == CS_OP_MEM:
                if op2.type == CS_OP_REG:
                    print(f"[REG KEY]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
                elif op2.type == CS_OP_IMM:
                    print(f"[MEM KEY]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
                
                #base = instr.reg_name(op1.mem.base)
                #if base in ("rbp", "rsp"):
                #    print(f"[STACK LOCAL VARIABLE]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

            else:
                print(f"[OTHER]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
