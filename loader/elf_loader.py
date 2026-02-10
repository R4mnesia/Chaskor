from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *

def elf_loader32(file):
    print("ELF 32 bits loader")

# CS_OP_IMM = immediate operands

def check_stripped(file):

    try: 
        with open(file, 'rb') as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name('.symtab')
            code = symtab.data()
            addr = symtab['sh_addr']

            for sym in symtab.iter_symbols():
                if sym.name == "main":
                    print(f"main addr: {hex(sym.entry['st_value'])}")
                    print(f"main addr: {sym.entry['st_value']}")
                    return hex(sym.entry['st_value'])
    except:
        return True


def elf_loader64(file):

    print("ELF 64 bits loader")
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name('.text')
        code = text.data()
        addr = text['sh_addr']

    #if check_stripped(file) == True:
    #    print("File is stripped")
    addr_main = check_stripped(file)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    #for instr_1 in md.disasm(code, addr):
    for instr in md.disasm(code, addr):

        if hex(instr.address) == addr_main:
            print(f"[MAIN]\n: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

        print(f"[CODE]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

        if instr.mnemonic == "jne" or instr.mnemonic == "je" or instr.mnemonic == "jmp":
            
            # addr of instruction > addr jump == loop
            if hex(instr.address) > instr.op_str:
                print(f"[LOOP]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
            
            # addr of instruction < addr jump == if/else         
            elif hex(instr.address) < instr.op_str:
                print(f"[CONDITION]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
        
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
