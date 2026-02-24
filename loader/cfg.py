from elftools.elf.elffile import ELFFile
from capstone.x86 import *

# ------------------- Instruction -------------------

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

# ------------------- BasicBlock -------------------

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


# ------------------- FunctionCFG -------------------

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

class FunctionCFG:
    def __init__(self, start_addr, instructions, file):
        self.start_addr = start_addr
        self.instructions = instructions
        self.block_map = {} # link address with block
        self.file = file

        self.functions = load_functions(file)

    def get_func_name(self, addr):
        for func in self.functions:
            if func["start"] <= addr < func["end"]:
                return func["name"]

        # stripped binary or extern function
        return f"func_{hex(addr)}"

    def build_blocks(self):

        addr_to_instr = {}
        for instr in self.instructions:
            addr_to_instr[instr.address] = instr

        worklist = [self.start_addr]
        print(f"worklist: {hex(worklist[0])}")
        visited = set()

        sorted_addrs = sorted(addr_to_instr.keys())
        #print(f"key: {addr_to_instr.keys()}")

        def get_next_addr(addr):
            if addr not in addr_to_instr:
                return None
            idx = sorted_addrs.index(addr)
            if idx + 1 < len(sorted_addrs):
                return sorted_addrs[idx + 1]
            return None

        while worklist:
            start_addr = worklist.pop()

            if start_addr in visited:
                continue
            if start_addr not in addr_to_instr:
                continue

            visited.add(start_addr)

            current_block = self.get_or_create_block(start_addr)
            addr = start_addr

            while True:
                if addr not in addr_to_instr:
                    break

                instr = addr_to_instr[addr]
                current_block.add_instruction(instr)

                if instr.is_ret():
                    break

                if instr.is_jump() and instr.operands[0].type == CS_OP_IMM:

                    target = instr.operands[0].imm
                    current_block.add_successor(self.get_or_create_block(target))
                    worklist.append(target)

                    # fall through for conditional jump
                    if instr.mnemonic != "jmp":
                        next_addr = get_next_addr(addr)
                        if next_addr:
                            current_block.add_successor(self.get_or_create_block(next_addr))
                            worklist.append(next_addr)
                    
                    if target in self.block_map and target < current_block.get_start_address():
                        # get predecessors block (start loop)
                        target_block = self.get_or_create_block(target)
                        target_block.set_loop()
                    break

                if instr.is_call() and instr.operands[0].type == CS_OP_IMM:

                    target = instr.operands[0].imm
                    current_block.add_successor(self.get_or_create_block(target))
                    worklist.append(target)
                    
                    if target in visited:
                        print(f"Target: {hex(target)}, start_addr {hex(current_block.get_start_address())}")

                    next_addr = get_next_addr(addr)
                    if next_addr:
                        current_block.add_successor(self.get_or_create_block(next_addr))
                        worklist.append(next_addr)
                    break

                if instr.is_xor():
                    xor_type = instr.get_xor_type()

                next_addr = get_next_addr(addr)

                if next_addr in self.block_map:
                    current_block.add_successor(self.get_or_create_block(next_addr))
                    worklist.append(next_addr)
                    break
                if not next_addr:
                    break

                addr = next_addr

    """def search_xor_key(self):
        for addr in sorted(self.block_map):
            block = self.block_map[addr]
            if block.is_loop == True:
                print(f"\n[LOOP] start: 0x{block.start_addr:x} {block.func_name}")
                for instr in block.instructions:
                    if instr.xor_type != None and instr.xor_type == "MIX":
                        for op in instr.operands:
                            inst = self.find_definition(op.reg, block.instructions, idx)
                        #print(f"[{instr.xor_type}]  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
                    else:
                        print(f"  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")"""

    def search_xor_key(self):
        for addr in sorted(self.block_map):
            block = self.block_map[addr]

            if block.is_loop:
                print(f"\n[LOOP] start: 0x{block.start_addr:x} {block.func_name}")

                for idx, instr in enumerate(block.instructions):
                    if instr.is_xor() and instr.xor_type == "MIX":
                        print(f"[KEY] 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

                        for op in instr.operands:
                            if op.type == CS_OP_REG:
                                def_instr, info = self.find_definition(op.reg, block.instructions, idx)
                                if def_instr:
                                    print(f"{info} comes from 0x{def_instr.address:x} {def_instr.mnemonic} {def_instr.op_str}")
                    else:
                        print(f"  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

    def find_definition(self, reg, instructions, current_index):
        for i in range(current_index - 1, -1, -1):
            instr = instructions[i]

            if instr.operands and instr.operands[0].type == CS_OP_REG:
                if instr.operands[0].reg == reg:
                    src_op = instr.operands[1]
                    if src_op.type == CS_OP_MEM and src_op.mem.scale > 1:
                        return instr, "key"
                    if src_op.type == CS_OP_MEM and src_op.mem.scale == 1:
                        return instr, "data"
        return None

    def get_or_create_block(self, addr):
        if addr not in self.block_map:
            func_name = self.get_func_name(addr)
            self.block_map[addr] = BasicBlock(addr, func_name)
        return self.block_map[addr]