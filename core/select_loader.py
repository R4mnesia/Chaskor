from loader import elf_loader, pe_loader

def select_arch(arch, file):

    if arch == "elf32":
        return elf_loader.elf_loader32, 32

    elif arch == "elf64":
        return elf_loader.elf_loader64, 64

    elif arch == "pe32":
        return pe_loader.pe_loader32, 32

    elif arch == "pe64":
        return pe_loader.pe_loader64, 64