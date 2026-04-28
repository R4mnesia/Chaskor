from elftools.elf.elffile import ELFFile
from capstone.x86 import *

def load_functions(file):
    functions = []
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        
        # stripped
        if not symtab:
            return functions

        ignore = ["_init", "_start", "frame_dummy", "register_tm_clones", "deregister_tm_clones"]

        for sym in symtab.iter_symbols():
            if sym.name not in ignore:
                start = sym['st_value']
                end = start + sym['st_size']
                functions.append({"name": sym.name, "start": start, "end": end})

    return functions