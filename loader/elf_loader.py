from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *
import elftools.common.utils as ecu
from .read_section_elf import *
from .search_elf import *
from .cfg import *

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

def extract_CFG_main(file):

    with open(file, 'rb') as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name('.text')
        code = text.data()
        addr = text['sh_addr']

    addr_main = check_stripped(file) # verif with protection

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    instructions = list(md.disasm(code, addr))
    start_addr_main, end_addr_main = get_start_and_end_main(file)

    instructions_main = []
    for instr in instructions:
        #if instr.address >= start_addr_main and instr.address <= end_addr_main:
        instructions_main.append(instr)

    instructions_main = [Instruction(i) for i in instructions_main]
    main_cfg = FunctionCFG(start_addr_main, instructions_main, file)
    main_cfg.build_blocks()


    print(main_cfg.start_addr)
    #for instr in main_cfg.instructions:
    #    print(f"[CODE]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
    #for block in main_cfg.blocks:
    #    print(f"\n[BLOCK] start: 0x{block.start_addr:x}")
    #    for instr in block.instructions:
    #        print(f"  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
    for addr in sorted(main_cfg.block_map):
        block = main_cfg.block_map[addr]
        print(f"\n[BLOCK] start: 0x{block.start_addr:x} {block.func_name}")
        for instr in block.instructions:
            print(f"  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
        
    #print(main_cfg.instructions)


def elf_loader64(file):
    
    extract_CFG_main(file)
    """print("ELF 64 bits loader")

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
                loop_search_main(instr, instructions, addr_main)
            if instr.mnemonic == "xor":
                xor_search(instr)
            elif instr.mnemonic == "call":
                intern_call_search(instr, file, addr_intern_func)
            else:
                print(f"[CODE]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
    print("###############")
    #print("\nINTERN FUNC:")
    #for name, addr in addr_intern_func:
    #    extract_function(file, instructions, name, addr)

    print(f"{addr_intern_func[0][0]}::::::{addr_intern_func[0][1]}")
    start_func, end_func = extract_intern_function_addr(file, addr_intern_func[0][0], addr_intern_func[0][1])
    extract_key_tab(instructions, instr, start_func, end_func)"""


"""
FIND_KEY_TAB:
find_loop --> find_xor --> if_xor_true --> find_register_increment --> back_before_loop_check_init_tab
find_loop --> find_xor --> if_xor_fals --> pass_loop
"""

"""
    mix_reg_true --> 
"""
def extract_key_tab(instructions, instr, addr_start, addr_end):
    
    key = []
    for i in range(len(instructions)):
        instr = instructions[i]

        if instr.address >= addr_start and instr.address <= addr_end:
            if instr.mnemonic == "jne" or instr.mnemonic == "je" or instr.mnemonic == "jmp":
                target_jmp = instr.operands[0].imm
                if target_jmp < instr.address and instr.address > addr_start:
                    addr_loop_start = target_jmp
                    addr_loop_end = instr.address

                    for i in range(len(instructions)):
                        lst = instructions[i]
                        if lst.address >= addr_start and lst.address <= addr_end:
                            if lst.address == addr_loop_start:
                                print(f"\n[LOOP_START]: \n0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")
                            if lst.mnemonic == "xor":
                                op1, op2 = lst.operands
                                if op1.type == CS_OP_REG and op2.type == CS_OP_REG: # xor ecx, ecx
                                    if op1.reg != op2.reg: # CHECK after this operand for 
                                        print(f"[MIX REG]: 0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")

                                if op1.type == CS_OP_MEM:
                                    if op2.type == CS_OP_REG:
                                        print(f"[REG KEY]: 0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")
                                    elif op2.type == CS_OP_IMM:
                                        print(f"[MEM KEY]: 0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")
                            if lst.mnemonic == "mov" and instructions[i + 1].mnemonic == "xor":
                                
                                # get type of register in xor
                                reg_op = instructions[i + 1].operands[1]
                                reg_id = reg_op.reg
                                reg_xor = instructions[i + 1].reg_name(reg_id)
                                print(f"reg_xor: {reg_xor}")

                                # get type of register in mov
                                reg_op_k = lst.operands[0]
                                reg_id_k = reg_op_k.reg
                                reg_key = lst.reg_name(reg_id_k)
                                print(f"reg_key: {reg_key}")

                                if reg_xor == reg_key:
                                    print("IS KEY")

                                # check if mov is key tab
                                # https://d-capstone.dpldocs.info/v0.0.2/capstone.x86.x86_op_mem.html
                                op = lst.operands[1]
                                
                                displacement_value = 0
                                base_register = 0
                                if op.type == X86_OP_MEM:
                                    mem = op.mem
                                    displacement_value = mem.disp
                                    base_register = mem.base
                                    """if (mem.base == X86_REG_RBP and
                                        mem.index == X86_REG_RAX and
                                        mem.scale == 4 and
                                        mem.disp == -0x40 and
                                        op.size == 4):
                                        print(f"[KEY]: 0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")"""
                                # find key
                                for i in range(len(instructions)):
                                    instr = instructions[i]
                                    if instr.address >= addr_start and instr.address <= addr_end:
                                        #print(f"[Code]: 0x{instr.address:x}:\t{instr.mnemonic}\t{lst.op_str}")

                                        if instr.mnemonic == "mov":
                                            print(f"[CODE]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

                                            op = instr.operands[0]
                                            mem = op.mem
                                            #print(f"type = {displacement_value}: {mem.disp}")
                                            if op.type == X86_OP_MEM and mem.disp == displacement_value and base_register == mem.base:
                                                index = i + 1
                                                print(f"[START KEY]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
                                                        

                            
                            elif addr_loop_start < lst.address < addr_loop_end:
                                print(f"0x{lst.address:x}:\t{lst.mnemonic}\t{lst.op_str}")

"""

                                    mov    eax,DWORD PTR [rbp + rax * 4 - 0x40] ; 0x40 = 64
                                    xor    edx,eax

"""