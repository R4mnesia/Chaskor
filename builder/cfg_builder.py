from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *
import elftools.common.utils as ecu
from cfg.cfg import *
# from cfg.cfg import * FunctionCFG, Instruction
from loader.utils import is_stripped
from loader.read_section_elf import get_start_and_end_main

def print_cfg(file, cfg):

    for addr in sorted(cfg.block_map):
        block = cfg.block_map[addr]
        if block.is_loop == True:
            print(f"\n[BLOCK LOOP] start: 0x{block.start_addr:x} {block.func_name}")
        else:
            print(f"\n[BLOCK] start: 0x{block.start_addr:x} {block.func_name}")
        for instr in block.instructions:
            if instr.xor_type != None:
                print(f"[{instr.xor_type}]  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
            else:
                print(f"  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

def build_cfg(start_addr, end_addr, instructions, file):
    instructions_main = []
    for instr in instructions:
        #if instr.address >= start_addr and instr.address <= end_addr:
        instructions_main.append(instr)

    instructions_main = [Instruction(i) for i in instructions_main]
    cfg = FunctionCFG(start_addr, instructions_main, file)
    cfg.build_blocks()
    return cfg

def extract_cfg_data(file, code, addr):
    #code, addr = load_text_section(file)

    stripped = is_stripped(file)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(code, addr))

    if stripped:
        print("[*] Binary is stripped")
        start_addr = addr
        end_addr = None
    else:
        print("[*] Binary is not stripped")
        start_addr, end_addr = get_start_and_end_main(file)

    cfg = build_cfg(start_addr, end_addr, instructions, file)
    #print_cfg(file)
    return cfg

