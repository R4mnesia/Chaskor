from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *
import elftools.common.utils as ecu
from .read_section_elf import *
from cfg.cfg import *

def load_text_section(file):
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name('.text')
        code = text.data()
        addr = text['sh_addr']
    return code, addr
    #print(cfg.instructions)

def elf_loader64(file):
    code, addr = load_text_section(file)
    return code, addr
    #extract_cfg_data(file)