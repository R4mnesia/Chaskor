from elftools.elf.elffile import ELFFile

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