from elftools.elf.elffile import ELFFile
from capstone.x86 import *

class Instruction:
    def __init__(self, capstone_instr):
        self.address = capstone_instr.address
        self.mnemonic = capstone_instr.mnemonic
        self.operands = capstone_instr.operands
        self.op_str = capstone_instr.op_str

        self.xor_type = None

    def is_jump(self):
        return self.mnemonic in ["jmp", "je", "jne"]

    def is_call(self):
        return self.mnemonic == "call"

    def is_ret(self):
        return self.mnemonic == "ret"

    def is_xor(self):
        return self.mnemonic == "xor"

    def get_xor_type(self):
        op1, op2 = self.operands
        if op1.type == CS_OP_REG and op2.type == CS_OP_REG: # xor ecx, ecx
            if op1.reg == op2.reg:
                self.xor_type = "ZERO"
            elif op1.reg != op2.reg: # CHECK after this operand for 
                self.xor_type = "MIX"
        elif op1.type == CS_OP_REG and op2.type == CS_OP_IMM: # xor ecx, 0x33
                self.xor_type = "KEY"
        #elif op1.type == CS_OP_MEM:
        #    if op2.type == CS_OP_REG:
        #        print(f"[REG KEY]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
        #    elif op2.type == CS_OP_IMM:
        #        print(f"[MEM KEY]: 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
        return self.xor_type