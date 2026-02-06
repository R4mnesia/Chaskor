import sys
from capstone import *
from elftools.elf.elffile import ELFFile
import argparse
from cli import args
from loader.select_loader import select_arch

if __name__ == "__main__":
    arch, file = args.parsing_arg()
    loader_func, bits = select_arch(arch, file)

    loader_func(file)
    print(f"Loader on {bits} bits")
    #disasm_elf(sys.argv[1])