from elftools.elf.elffile import ELFFile
# ------------------- Instruction -------------------

class Instruction:
    def __init__(self, capstone_instr):
        self.address = capstone_instr.address
        self.mnemonic = capstone_instr.mnemonic
        self.operands = capstone_instr.operands
        self.op_str = capstone_instr.op_str

    def is_jump(self):
        return self.mnemonic in ["jmp", "je", "jne"]

    def is_call(self):
        return self.mnemonic == "call"

    def is_ret(self):
        return self.mnemonic == "ret"

    def is_xor(self):
        return self.mnemonic == "xor"


# ------------------- BasicBlock -------------------

class BasicBlock:
    def __init__(self, start_addr, func_name=None):
        self.start_addr = start_addr
        self.func_name = func_name
        self.instructions = []
        self.successors = [] # basicblock class ->> next

    def add_instruction(self, instr):
        self.instructions.append(instr)

    def add_successor(self, block):
        self.successors.append(block)


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
        #self.blocks = [] # basic block class
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
        current_block = None

        for i, instr in enumerate(self.instructions):
            if current_block is None:
                current_block = self.get_or_create_block(instr.address)

            current_block.add_instruction(instr)

            # end of block -> jump / call / ret
            if instr.is_jump():
                
                target = instr.operands[0].imm
                successor_block = self.get_or_create_block(target)
                current_block.add_successor(successor_block)

                # fall through for conditional jump
                if instr.mnemonic != "jmp":
                    if len(self.instructions) > i + 1:
                        fall_addr = self.instructions[i + 1].address
                        fall_block = self.get_or_create_block(fall_addr)
                        current_block.add_successor(fall_block)

                current_block = None
            elif instr.is_ret():
                current_block = None

    def get_or_create_block(self, addr):
        if addr not in self.block_map:
            func_name = self.get_func_name(addr)
            self.block_map[addr] = BasicBlock(addr, func_name)
        return self.block_map[addr]

"""instructions = list(md.disasm(code, addr))
instructions = [Instruction(i) for i in instructions]

start_addr_main = main_addr
instructions_main = [] # read instr for call functionCFG
main_cfg = FunctionCFG("main", start_addr_main, instructions_main)
main_cfg.build_blocks()"""

#func_cfg = FunctionCFG("func_a", start_addr_func, instructions_func)
#func_cfg.build_blocks()
#func_cfg.blocks[0]