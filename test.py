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
    def __init__(self, start_addr):
        self.start_addr = start_addr
        self.instructions = []
        self.successors = [] # basicblock class ->> next

    def add_instruction(self, instr):
        self.instructions.append(instr)

    def add_successor(self, block):
        self.successors.append(block)


# ------------------- FunctionCFG -------------------

class FunctionCFG:
    def __init__(self, name, start_addr, instructions):
        self.name = name
        self.start_addr = start_addr
        self.instructions = instructions
        self.blocks = [] # basic block class

    def build_blocks(self):
        current_block = None

        for instr in self.instructions:
            if current_block is None:
                current_block = BasicBlock(instr.address)

            current_block.add_instruction(instr)

            # end of block -> jump / call / ret
            if instr.is_jump() or instr.is_call() or instr.is_ret():
                target = None
                if instr.is_jump() or instr.is_call():
                    target = instr.operands[0].imm

                # create successor if jump
                if target is not None:
                    successor_block = BasicBlock(target)
                    current_block.add_successor(successor_block)

                # end of actual block
                self.blocks.append(current_block)
                current_block = None

        if current_block is not None and current_block.instructions:
            self.blocks.append(current_block)

instructions = list(md.disasm(code, addr))
instructions = [Instruction(i) for i in instructions]

start_addr_main = main_addr
instructions_main = [] # read instr for call functionCFG
main_cfg = FunctionCFG("main", start_addr_main, instructions_main)
main_cfg.build_blocks()

#func_cfg = FunctionCFG("func_a", start_addr_func, instructions_func)
#func_cfg.build_blocks()
#func_cfg.blocks[0]