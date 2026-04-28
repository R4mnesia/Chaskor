from elftools.elf.elffile import ELFFile
from capstone.x86 import *

class BasicBlock:
    def __init__(self, start_addr, func_name=None):
        self.start_addr = start_addr
        self.func_name = func_name
        self.instructions = []
        self.successors = [] # basicblock class ->> next
        self.predecessors = []

        self.is_loop = False

    def add_instruction(self, instr):
        self.instructions.append(instr)

    def add_successor(self, block):
        self.successors.append(block)
        block.predecessors.append(self)

    def add_predecessors(self, block):
        self.predecessors.append(block)
    
    def set_loop(self):
        self.is_loop = True

    def get_start_address(self):
        return self.start_addr