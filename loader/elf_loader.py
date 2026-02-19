from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *
import elftools.common.utils as ecu
from .read_section_elf import *
from .search_elf import *

def get_start_and_end_main(file):

    with open(file, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        code = symtab.data()
        addr = symtab['sh_addr']
    
        for sym in symtab.iter_symbols():
            if sym.name == "main":
                start = sym.entry['st_value']
                size = sym.entry['st_size']
                end = start + size
                return start, end

def get_main_list(instructions, addr_main):
    main = [""]
    for instr in instructions:
        if instr.address >= addr_main:
            main.append(f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
    return main
                
def elf_loader64(file):
    print("ELF 64 bits loader")

    base_addr, code = read_rodata(file)
    dump_hex(base_addr, code)

    with open(file, 'rb') as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name('.text')
        code = text.data()
        addr = text['sh_addr']

    addr_main = check_stripped(file) # verif with protection

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True    

    instructions = list(md.disasm(code, addr))

    start_main, end_main = get_start_and_end_main(file)

    loop = [""]
    addr_intern_func = []
    
    print("<main>:")
    for instr in instructions:

        if instr.address >= start_main and instr.address <= end_main:
            
            if instr.mnemonic == "jne" or instr.mnemonic == "je" or instr.mnemonic == "jmp":
                loop_search(instr, instructions, addr_main)
            if instr.mnemonic == "xor":
                xor_search(instr)
            elif instr.mnemonic == "call":
                intern_call_search(instr, file, addr_intern_func)
            else:
                print(f"[CODE]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

    print("\nINTERN FUNC:")
    for name, addr in addr_intern_func:
        extract_function(file, instructions, name, addr)
    