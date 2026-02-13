from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *
import elftools.common.utils as ecu

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
                    return sym.entry['st_value']
    except:
        return True


def read_rodata(file):
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        rodata = elf.get_section_by_name('.rodata')
        code = rodata.data()
        base_addr = rodata['sh_addr']

    print(f"\n{hex(base_addr)} @.rodata: \n{code}")
    return base_addr, code

def dump_hex(base_addr, data):
    
    for i in range(0, len(data), 16): # increment 16
        chunk = data[i:i + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        print(f"  {base_addr + i:08x}  {hex_bytes}")
    print("")

def elf_loader64(file):
    print("ELF 64 bits loader")

    base_addr, code = read_rodata(file)
    dump_hex(base_addr, code)

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

    instructions = list(md.disasm(code, addr))
    loop = [""]
    for instr in instructions:

        if hex(instr.address) == addr_main:
            print(f"\n< main >: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

        print(f"[CODE]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

        if instr.mnemonic == "jne" or instr.mnemonic == "je" or instr.mnemonic == "jmp":

            target_jmp = instr.operands[0].imm

            # addr of instruction > addr jump == loop
            if target_jmp < instr.address and instr.address > addr_main:
                print(f"\n[LOOP_END]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
                
                addr_loop_start = target_jmp
                addr_loop_end = instr.address

                for lst in instructions:
                    if lst.address == addr_loop_start:
                        print(f"\n[LOOP_START]: 0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")
                    if addr_loop_start < lst.address < addr_loop_end:
                        print(f"0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")
                        loop.append(f"0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")
                print("")

            
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

    #print(f"LOOP:\n")
    #for i in loop:
    #    print(f"{i}")