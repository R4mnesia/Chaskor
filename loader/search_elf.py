from capstone.x86 import *
from elftools.elf.elffile import ELFFile
import elftools.common.utils as ecu
from .read_section_elf import read_symtab

def xor_search(instr):
    if instr.mnemonic == "xor":
        op1, op2 = instr.operands

        if op1.type == CS_OP_REG and op2.type == CS_OP_REG: # xor ecx, ecx
            
            if op1.reg == op2.reg:
                print(f"[ZERO]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
            elif op1.reg != op2.reg: # CHECK after this operand for 
                print(f"[MIX REG]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

        elif op1.type == CS_OP_REG and op2.type == CS_OP_IMM: # xor ecx, 0x33
            print(f"[KEY]:  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

        elif op1.type == CS_OP_MEM:
            if op2.type == CS_OP_REG:
                print(f"[REG KEY]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
            elif op2.type == CS_OP_IMM:
                print(f"[MEM KEY]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
        return True
    return False

def loop_search_main(instr, instructions, addr_main):

    target_jmp = instr.operands[0].imm

    # addr of instruction > addr jump == loop
    if target_jmp < instr.address and instr.address > addr_main:
        addr_loop_start = target_jmp
        addr_loop_end = instr.address

        for lst in instructions:
            if lst.address == addr_loop_start:
                print(f"\n[LOOP_START]: \n0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")
            if addr_loop_start < lst.address < addr_loop_end:
                print(f"0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")
        print("")

"""
######################
INTERN FUNCTION SEARCH
######################
"""

def intern_call_search(instr, file, addr_intern_func):

    func_addr = instr.operands[0].imm
    if function_is_intern(file, func_addr):
        func_name, addr_name = read_symtab(file, instr.operands[0].imm)
        addr_intern_func.append((func_name, func_addr))
        print(f"[INTERN FUNCTION {func_name}]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}\n")
    else:
        print(f"[CALL EXTERN FUNCTION]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

def function_is_intern(file, target_addr):
    
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        text_section = elf.get_section_by_name('.text')
        text_start = text_section['sh_addr']
        text_end = text_start + text_section['sh_size']
    

        if text_start <= target_addr < text_end:
            #print(f"Call intern: {hex(target_addr)} (function of binary)")
            return True
        else:
            #print("Call extern (libc / plt / dynsym)")
            return False

def extract_intern_function_addr(file, func_name, func_addr):
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        code = symtab.data()
        base_addr = symtab['sh_addr']

        if not symtab:
            print("not")

        for sym in symtab.iter_symbols():
            if func_addr == sym['st_value']: #and sym.name == func_name:
                start = sym.entry['st_value']
                size = sym.entry['st_size']
                end = start + size
                return start, end
    return 0, 0

def loop_search_in_func(instr, instructions, addr_start):
    target_jmp = instr.operands[0].imm

    # addr of instruction > addr jump == loop
    if target_jmp < instr.address and instr.address > addr_start:
        addr_loop_start = target_jmp
        addr_loop_end = instr.address

        for lst in instructions:
            if lst.address == addr_loop_start:
                print(f"\n[LOOP_START]: \n0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")
            if addr_loop_start < lst.address < addr_loop_end:
                print(f"0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")
        print("")

def extract_function(file, instructions, func_name, func_addr):

    start_func, end_func = extract_intern_function_addr(file, func_name, func_addr)
    if start_func == 0 and end_func == 0:
        print("NULL ADDR")
        return 

    print(f"Function {func_name}:")
    addr_intern_func = []

    for instr in instructions:
        if instr.address >= start_func and instr.address <= end_func:
            if instr.mnemonic == "jne" or instr.mnemonic == "je" or instr.mnemonic == "jmp":
                loop_search_in_func(instr, instructions, start_func)
            if instr.mnemonic == "xor":
                xor_search(instr)
            elif instr.mnemonic == "call":
                intern_call_search(instr, file, addr_intern_func)
            else:
                print(f"[CODE]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")