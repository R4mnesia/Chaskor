from elftools.elf.elffile import ELFFile
from capstone.x86 import *
from .instructions import Instruction
from .blocks import BasicBlock
from .utils import load_functions

class FunctionCFG:
    def __init__(self, start_addr, instructions, file):
        self.start_addr = start_addr
        self.instructions = instructions
        self.block_map = {} # link address with block
        self.file = file

        self.functions = load_functions(file)

        self.addr_to_instr = {instr.address: instr for instr in self.instructions}  # addr --> instr
        self.sorted_addrs = sorted(self.addr_to_instr.keys())
        self.addr_index = {addr: i for i, addr in enumerate(self.sorted_addrs)}     # index of addr

    def get_func_name(self, addr):
        for func in self.functions:
            if func["start"] <= addr < func["end"]:
                return func["name"]

        # stripped binary or extern function
        return f"func_{hex(addr)}"

    def handle_jump(self, instr, current_block, worklist, addr):
        target = instr.operands[0].imm
        current_block.add_successor(self.get_or_create_block(target))
        worklist.append(target)

        # fall through for conditional jump
        if instr.mnemonic != "jmp":
            next_addr = self.get_next_addr(addr)
            if next_addr:
                current_block.add_successor(self.get_or_create_block(next_addr))
                worklist.append(next_addr)
                    
        if target in self.block_map and target < current_block.get_start_address():
            # get predecessors block (start loop)
            target_block = self.get_or_create_block(target)
            target_block.set_loop()

    def handle_call(self, instr, current_block, worklist, visited, addr):
        target = instr.operands[0].imm

        current_block.add_successor(self.get_or_create_block(target))
        worklist.append(target)
        
        if target in visited:
            print(f"Target: {hex(target)}, start_addr {hex(current_block.get_start_address())}")

        next_addr = self.get_next_addr(addr)
        if next_addr:
            current_block.add_successor(self.get_or_create_block(next_addr))
            worklist.append(next_addr)

    def get_next_addr(self, addr):
        if addr not in self.addr_to_instr:
            return None
        idx = self.addr_index[addr]
        if idx + 1 < len(self.sorted_addrs):
            return self.sorted_addrs[idx + 1]
        return None

    def build_blocks(self):

        worklist = [self.start_addr]
        print(f"worklist: {hex(worklist[0])}")
        visited = set()

        while worklist:
            start_addr = worklist.pop()

            if start_addr in visited:
                continue
            if start_addr not in self.addr_to_instr:
                continue

            visited.add(start_addr)

            current_block = self.get_or_create_block(start_addr)
            addr = start_addr

            while True:
                if addr not in self.addr_to_instr:
                    break

                instr = self.addr_to_instr[addr]
                current_block.add_instruction(instr)

                if instr.is_ret():
                    break

                if instr.is_jump() and instr.operands[0].type == CS_OP_IMM:
                    self.handle_jump(instr, current_block, worklist, addr)
                    break

                if instr.is_call() and instr.operands[0].type == CS_OP_IMM:
                    self.handle_call(instr, current_block, worklist, visited, addr)
                    break

                if instr.is_xor():
                    xor_type = instr.get_xor_type()
                    self.search_xor_key(xor_type)


                next_addr = self.get_next_addr(addr)

                if next_addr and next_addr in self.block_map:
                    current_block.add_successor(self.get_or_create_block(next_addr))
                    worklist.append(next_addr)
                    break
                if not next_addr:
                    break

                addr = next_addr

    def search_xor_key(self, xor_type):
        if xor_type != "MIX":
            return
        for addr in sorted(self.block_map):
            block = self.block_map[addr]

            block_predecessors1 = self.block_map[addr].predecessors
            block_predecessors = init_blocks = [b for b in block_predecessors1 if b.start_addr < block.start_addr]
            if block.is_loop:
                print(f"addr: {hex(addr)}")

                print(f"\n[LOOP] start: 0x{block.start_addr:x} {block.func_name}")

                for idx, instr in enumerate(block.instructions):
                    if instr.is_xor() and instr.xor_type == "MIX":
                        #print(f"[KEY] 0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

                        for op in instr.operands:
                            if op.type == CS_OP_REG:
                                print(f"[CODE] 0x{op.reg}:\t{instr.mnemonic}\t{instr.op_str}")

                                def_instr, info = self.find_definition(op.reg, block.instructions, idx)
                                if def_instr:
                                    
                                    if info == "key":
                                        print("Pred_BLOCK")
                                        self.find_definition_on_predecessor_block(block_predecessors, op)
                                    print(f"{info} comes from 0x{def_instr.address:x} {def_instr.mnemonic} {def_instr.op_str}")
                    else:
                        print(f"  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

    def find_definition(self, reg, instructions, current_index):
        for i in range(current_index - 1, -1, -1):
            instr = instructions[i]

            if instr.operands and instr.operands[0].type == CS_OP_REG:
                if instr.operands[0].reg == reg:
                    src_op = instr.operands[1]

                    # [base + index*scale + displacement]
                    if src_op.type == CS_OP_MEM and src_op.mem.scale > 1:
                        return instr, "key"
                    if src_op.type == CS_OP_MEM and src_op.mem.scale == 1:
                        return instr, "data"
        return None

    def find_definition_on_predecessor_block(self, block_predecessors, op):

        #op.mem.base = rbp
        #op.mem.index = X86_REG_RAX
        #op.mem.scale = 4
        #op.mem.disp = -0x20
        #op.size = 4 -> dword
        
        print("#################\n")
        for pred_block in block_predecessors:
            for idx, instr in enumerate(pred_block.instructions):
                print(f"  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

        print("#################\n")

        #    print(f"op: {op}, def_instr[1]: {def_instr.operands[1]}")
            #if instr.operands and op == def_instr.operands[1]:



    def get_or_create_block(self, addr):
        if addr not in self.block_map:
            func_name = self.get_func_name(addr)
            self.block_map[addr] = BasicBlock(addr, func_name)
        return self.block_map[addr]