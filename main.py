import sys
from capstone import *
from elftools.elf.elffile import ELFFile
import argparse
from cli import args
from core.select_loader import select_arch
from builder.cfg_builder import extract_cfg_data, print_cfg

"""
if __name__ == "__main__":
    arch, file = args.parsing_arg()
    loader_func, bits = select_arch(arch, file)

    loader_func(file)
    #disasm_elf(sys.argv[1])"""

if __name__ == "__main__":

    arch, file = args.parsing_arg()

    loader_func, bits = select_arch(arch, file)

    # 1. load
    code, addr = loader_func(file)

    # 2. build CFG
    cfg = extract_cfg_data(file, code, addr)

    # 3. print
    print_cfg(file, cfg)

