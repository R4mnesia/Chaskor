from . import pe_loader, elf_loader

def select_arch(arch, file):

    if arch == "elf32":
        loader_func = elf_loader.elf_loader32
        bits = 32
    elif arch == "elf64":
        loader_func = elf_loader.elf_loader64
        bits = 64
    elif arch == "pe32":
        loader_func = pe_loader.pe_loader32
        bits = 32
    elif arch == "pe64":
        loader_func = pe_loader.pe_loader64
        bits = 64
    
    return loader_func, bits