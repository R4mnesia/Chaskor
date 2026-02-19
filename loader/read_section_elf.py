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

def read_symtab(file, target_addr):
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        code = symtab.data()
        base_addr = symtab['sh_addr']

        if not symtab:
            print("not")
        
        ignore = ["_init", "_start", "frame_dummy", "register_tm_clones", "deregister_tm_clones"]
        for sym in symtab.iter_symbols():
            #print(f"symtab sym.name: {sym.name}")
            if target_addr == sym['st_value'] and sym.name not in ignore:
                #print(f"[CALL INTERN FUNCTION {sym.name}]: {hex(target_addr)}\n")
                return sym.name, hex(target_addr)

    #print(f"\n{hex(base_addr)} @.symtab: \n{code}")
    #dump_hex(base_addr, code)
    return base_addr, code

def read_dynsym(file, target_addr):
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name('.dynsym')
        relplt = elf.get_section_by_name('.rela.plt') or elf.get_section_by_name('.rel.plt')
        #print(f"{file.find_at_addr(target_addr)}")

        if not dynsym:
            print("not")
        for rel in relplt.iter_relocations():

            symbol = dynsym.get_symbol(rel['r_info_sym'])
            func_name = symbol.name
            got_address = rel['r_offset']
            
            print(f"got_addr {hex(got_address)}")
            print(f"{func_name} -> GOT @ {hex(got_address)}")
