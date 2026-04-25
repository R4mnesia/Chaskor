from elftools.elf.elffile import ELFFile

def is_stripped(file):
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        return elf.get_section_by_name('.symtab') is None