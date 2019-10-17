#coding=utf-8

import collections
import claripy
import angr
import pyvex
import am_graph
from keystone import *
from unicorn import *
from unicorn.arm_const import *
from capstone import *
from capstone.arm import *


def is_ollvm_branch(index, insn):
    if (index + 1) > len(insn):
        return False
    if insn[index].mnemonic.startswith('movw') and len(insn[index].mnemonic) == 6 and insn[index+1].mnemonic.startswith('movt') and len(insn[index+1].mnemonic) == 6:
        return True
    return False

def reg_ctou(regname):#
    # This function covert capstone reg name to unicorn reg const.
    type1 = regname[0]
    if type1 == 'r':
        idx = int(regname[1:])
        return idx + UC_ARM_REG_R0
    elif regname == 'sp':
        return UC_ARM_REG_SP 
    elif regname == 'pc':
        return UC_ARM_REG_PC
    elif regname == 'fp':
        return UC_ARM_REG_FP
    return None

def asm_no_branch(ori,dist):
    global ks
    print ("patch addr: 0x%x--> b #0x%x" % (ori,dist))
    ins, count  = ks.asm(("b #0x%x" % dist),ori)
    return  ins

def asm_has_branch(ori,dist1,dist2,cond):
    global ks
    print ("patch addr: 0x%x--> b%s #0x%x;b #0x%x" % (ori,cond,dist1,dist2))
    ins, count = ks.asm("b%s #0x%x;b #0x%x" % (cond,dist1,dist2),ori)
    return ins

def get_context():
    global mu
    regs = []
    for i in range(12):
        idx = UC_ARM_REG_R0 + i
        regs.append(mu.reg_read(idx))
    regs.append(mu.reg_read(UC_ARM_REG_SP))
    regs.append(mu.reg_read(UC_ARM_REG_FP))
    regs.append(mu.reg_read(UC_ARM_REG_IP))
    return regs

def set_context(regs):
    global mu
    if regs == None:
        return
    for i in range(12):
        idx = UC_ARM_REG_R0 + i
        mu.reg_write(idx, regs[i])
    mu.reg_write(UC_ARM_REG_SP, regs[12])
    mu.reg_write(UC_ARM_REG_FP, regs[13])
    mu.reg_write(UC_ARM_REG_IP, regs[14])

# callback for memory exception
def hook_mem_access(uc, type, address, size, value, userdata):
    pc = uc.reg_read(UC_ARM_REG_PC)
    print ('pc:%x type:%d addr:%x size:%x' % (pc,type,address,size))
    #uc.emu_stop()
    return False

def hook_code(uc, address, size, user_data):
    
    global base
    global is_debug
    global is_success
    global list_trace
    global relevant_block_addrs
    global next_real_block_addr
    global block_start_addr
    global branch_control
    global list_blocks

    ban_ins = ["bl"]

    if is_success:
        mu.emu_stop()
        return

    if (address + base) > end:
        uc.emu_stop()
        return

    for ins in md.disasm(bin[address:address + size], address):
        #print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
        #print(">>> 0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
        #print

        if (address + base) in relevant_block_addrs:
            if list_trace.has_key(address):
                print ("sssssss")
                #ch = raw_input("This maybe a fake block. codesign:%s " % get_code_sign(list_blocks[address]))
                uc.emu_stop()
            else:
                list_trace[address] = 1

        if (address + base) in relevant_block_addrs and address != block_start_addr:
            is_success = True
            next_real_block_addr = address
            #print 'find:%x' % address
            uc.emu_stop()
            return
        
        #是否跳过指令
        flag_pass = False
        for b in ban_ins:
            if ins.mnemonic.startswith(b):
                flag_pass = True
                break
            
        #只允许对栈的操作
        if ins.op_str.find('[') != -1:
            if ins.op_str.find('[sp') == -1:
                flag_pass = True
                for op in ins.operands:
                    if op.type == ARM_OP_MEM:
                        addr = 0
                        if op.value.mem.base != 0:
                            addr += mu.reg_read(reg_ctou(ins.reg_name(op.value.mem.base)))
                        elif op.value.index != 0:
                            addr += mu.reg_read(reg_ctou(ins.reg_name(op.value.mem.index)))
                        elif op.value.disp != 0:
                            addr += op.value.disp
                        if addr >= 0x80000000 and addr < 0x80000000 +  0x10000 * 8:
                            flag_pass = False
        if flag_pass:
            #print("will pass 0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
            uc.reg_write(UC_ARM_REG_PC, address + size)
            return      
        
        #breaks 0x31300
        if address in [ 0xB72EC ] or is_debug:
            is_debug = True
            print("0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
            while True:
                c = raw_input('>')
                if c == '':
                    break
                if c == 's':
                    uc.emu_stop()
                    return
                if c == 'r':
                    is_debug = False
                    break
                if c[0] == '!':
                    reg = reg_ctou(c[1:])
                    print ("%s=%x (%d)" % (c[1:], mu.reg_read(reg),mu.reg_read(reg)))
                    continue

        if ins.id == ARM_INS_POP:
            uc.reg_write(UC_ARM_REG_PC, -1)
            is_success = False
            print ("ret ins..")
            mu.emu_stop()

        #ollvm branch
        if ins.mnemonic.startswith('movw') and len(ins.mnemonic) == 6:
            ureg = reg_ctou(ins.reg_name(ins.operands[0].value.reg))
            imm = ins.operands[1].value.imm

            if branch_control == 1:
                uc.reg_write(ureg, imm)
            uc.reg_write(UC_ARM_REG_PC, address + size)

        if ins.mnemonic.startswith('movt') and len(ins.mnemonic) == 6:
            ureg = reg_ctou(ins.reg_name(ins.operands[0].value.reg))
            imm = ins.operands[1].value.imm

            v1 = uc.reg_read(ureg)
            v1 = v1 | (imm << 16)

            if branch_control == 1:
                uc.reg_write(ureg, v1)
            uc.reg_write(UC_ARM_REG_PC, address + size)

def find_path(start_addr,branch = None):
    global real_blocks
    global bin
    global base
    global mu
    global list_trace
    global block_start_addr
    global next_real_block_addr
    global is_success
    global branch_control
    try:
        list_trace = {}
        block_start_addr = start_addr - base
        is_success = False
        next_real_block_addr = 0
        branch_control = branch
        mu.emu_start(start_addr - base, 0x10000)

    except UcError as e:
        pc = mu.reg_read(UC_ARM_REG_PC)
       # print ("111 pc:%x" % pc)
        if pc > 0 and pc < len(bin):
            pc = pc + base + 4
            #mu.reg_write(UC_ARM64_REG_PC, pc + 4)
            return find_path(pc, branch)
        else:
            print("ERROR: %s  pc:%x" % (e,pc))
    if is_success:
        return next_real_block_addr + base
    return None

def fix(bin):
    global base

    queue = [start]
    check = []
    while len(queue) > 0:
        pc = queue.pop()
        if pc in check:
            continue
        check.append(pc)

        node = None
        for relevant in relevants:
            if relevant.addr == pc:
                node = relevant

        block = project.factory.block(pc, size=node.size)

        if(len(flow[pc]) == 2):
            founded = False

            for index in range(len(block.capstone.insns)-1, -1, -1):
                ins = block.capstone.insns[index]

                if is_ollvm_branch(index, block.capstone.insns):
                    patch_offset = ins.address - base
                    branch1 = flow[pc][0] - base
                    branch2 = flow[pc][1] - base
                    cond = ins.insn.mnemonic[-2:]
                    opcode = asm_has_branch(patch_offset, branch1, branch2, cond)
                    op_str = "".join([ chr(i) for i in opcode ])

                    bin = bin[:patch_offset] + op_str + bin[patch_offset+len(op_str):]
                    founded = True

                    break
                    #ins, count = ks.asm("nop")
                    #op_str += "".join([ chr(i) for i in ins])
  
            if founded == True:
                for i in range(index+2, len(block.capstone.insns)):
                    ins = block.capstone.insns[i]
                    patch_offset = ins.address - base
                    if ins.id == ARM_INS_B:
                        ins, count = ks.asm("nop")
                        op_nop_str = "".join([ chr(i) for i in ins])
                        bin = bin[:patch_offset] + op_nop_str + bin[patch_offset+len(op_nop_str):]
                    else:
                        swap_offset = patch_offset - 8
                        
                        opcode = asm_has_branch(swap_offset+ins.size, branch1, branch2, cond)
                        op_str = "".join([ chr(i) for i in opcode ])
                        
                        bin = bin[:swap_offset] + bin[patch_offset:patch_offset+ins.size] + op_str + bin[patch_offset+ins.size:]    

                        '''
                        opcode = ks.asm(ins.op_str) + asm_has_branch(swap_offset+ins.size, branch1, branch2, cond)  
                        op_str = "".join([ chr(i) for i in opcode ])
                        
                        bin = bin[:swap_offset] + op_str + bin[patch_offset+ins.size:]     
                        '''        
            else:
                print ("error !!!!!!")
                raw_input()
                
        if(len(flow[pc]) == 1):
            patch_offset = block.capstone.insns[-1].address - base
            branch = flow[pc][0] - base
            opcode = asm_no_branch(patch_offset, branch)
            op_str = "".join([ chr(i) for i in opcode ])
            bin = bin[:patch_offset] + op_str + bin[patch_offset+len(op_str):]
        
        if(len(flow[pc]) == 0):
            #ret block
            continue


        for i in flow[pc]:
            if i != None:
                queue.append(i)
                
    return bin

'''
def symbolic_execution(start_addr, hook_addr=None, state=None, modify=None, inspect=False):
    def retn_procedure(state):
        global project
        ip = state.se.eval(state.regs.ip)
        project.unhook(ip)
        return    
    
    #只处理真实块的条件分支
    def statement_inspect(state):
        global modify_value

        #IR 表达式 数组
        expressions = list(state.scratch.irsb.statements[state.inspect.statement].expressions)
        
        state.scratch.irsb.statements[state.inspect.statement].pp()
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):   
            state.scratch.temps[expressions[0].cond.tmp] = modify_value    
            #清空statement
            #state.inspect._breakpoints['statement'] = []
    
    global project, relevant_block_addrs, modify_value

    if state == None:
        state = project.factory.blank_state(addr=start_addr, remove_options={angr.sim_options.LAZY_SOLVES})
    if hook_addr != None:
        for i in hook_addr:
            project.hook(hook_addr, retn_procedure, length=4)
    if inspect:
        state.inspect.b('statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)

    sm = project.factory.simulation_manager(state)
    sm.step()

    while len(sm.active) > 0:
        if len(sm.active) != 1:
            print 1
        for active_state in sm.active:
            print hex(active_state.addr)
            if active_state.addr in relevant_block_addrs:
                #sm.step()
                return (active_state.addr, active_state)
        sm.step()
'''

def get_relevant_nodes(supergraph, node, founded_node):
    global relevant_nodes
    branch_nodes = list(supergraph.successors(node))

    if len(branch_nodes) == 1 and branch_nodes[0] in founded_node:
        if node in relevant_nodes:
            for i in supergraph.predecessors(node):
                relevant_nodes.append(i)
        else:
            relevant_nodes.append(node)
    else:
        founded_node.append(node)      
        for i in branch_nodes:
            if i not in founded_node:
                get_relevant_nodes(supergraph, i, founded_node)
    
base = 0x400000
start = 0x11D94 + base
end = 0x14CF8 + base

filename = "libdynamicMono.so"
new_filename = filename + '.new'

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
md.detail = True

with open(filename, 'rb') as fp:
    bin = fp.read()

project = angr.Project(filename, load_options={'auto_load_libs': False})
#cfg = project.analyses.CFGAccurate(context_sensitivity_level=3,keep_state=True,starts=[start])
cfg = project.analyses.CFGFast(normalize=True,regions=[(start, end)])
#start += project.entry
target_function = cfg.functions.get(start)

assert target_function != None

supergraph = am_graph.to_supergraph(target_function.transition_graph)

retn_node = None
prologue_node = None #序言块

for node in supergraph.nodes():
    if supergraph.in_degree(node) == 0:
        prologue_node = node
    if supergraph.out_degree(node) == 0:
        if retn_node == None:  
            retn_node = node 
        elif retn_node != None:
            assert len(list(supergraph.predecessors(node))) == 1
            assert len(list(supergraph.predecessors(retn_node))) == 1
            assert list(supergraph.predecessors(retn_node))[0] == list(supergraph.predecessors(node))[0]
            
            retn_node = list(supergraph.predecessors(retn_node))[0]


if prologue_node is None or prologue_node.addr != start:
    print("Something must be wrong...")
    exit(0)

main_dispatcher_node = list(supergraph.successors(prologue_node))[0]
relevant_nodes = []
get_relevant_nodes(supergraph, main_dispatcher_node, [])
relevant_block_addrs = [(node.addr) for node in relevant_nodes]

print('*******************relevant blocks************************')
print('prologue: %#x' % start)
print('main_dispatcher: %#x' % main_dispatcher_node.addr)
print('retn: %#x' % retn_node.addr)
print('relevant_blocks:', [hex(addr) for addr in relevant_block_addrs])

print('*******************symbolic execution*********************')
relevants = relevant_nodes
relevants.append(prologue_node)
relevants_without_retn = list(relevants)
relevants.append(retn_node)
for i in supergraph.successors(retn_node):
    relevants.append(i)

relevant_block_addrs.extend([prologue_node.addr, retn_node.addr])

flow = collections.defaultdict(list)
modify_value = None
patch_instrs = {}

'''
state = project.factory.blank_state(addr=prologue_node.addr, remove_options={angr.sim_options.LAZY_SOLVES})
sm = project.factory.simulation_manager(state)
sm.step()

queue = [(prologue_node.addr, None)]

while len(queue) != 0:
    env = queue.pop()

    address = env[0]
    state = env[1]

    node = None
    for relevant in relevants:
        if relevant.addr == address:
            node = relevant
    block = project.factory.block(address, size=node.size)

    if node.addr in flow:
        #print "???"
        continue
    
    has_branches = False
    hook_addr = []

    #代码块中有ollvm生成的分支
    for ins in block.capstone.insns:
        if ins.insn.mnemonic.startswith('csel'):
            has_branches = True
        elif ins.insn.mnemonic.startswith('bl'):
            hook_addr.append(ins.insn.address)

    if has_branches == True:
        (p1, next_state) = symbolic_execution(address, hook_addr, state, claripy.BVV(0, 1), True)
        (p2, next_state) = symbolic_execution(address, hook_addr, state, claripy.BVV(1, 1), True)
        print hex(p1)
        print hex(p2)
        if p1 != None:
            queue.append((p1, next_state))
            flow[node].append(p1)
        if p1 == p2:
            p2 = None

        if p2 != None:
            queue.append((p2, next_state))
            flow[node].append(p2)
    else:
        (p, next_state) = symbolic_execution(address, hook_addr, state)
        print hex(p)
        if p != None:
            queue.append((p, next_state))
            flow[node].append(p)
'''

mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
#init stack
mu.mem_map(0x80000000,0x10000 * 8)
# map 4MB memory for this emulation
mu.mem_map(0, 4 * 1024 * 1024)

# write machine code to be emulated to memory
mu.mem_write(0, bin)
mu.reg_write(UC_ARM_REG_SP, 0x80000000 + 0x10000 * 6)
mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_access)

list_trace = {}
is_debug = False
queue = [(start, None)]

while len(queue) != 0:

    env = queue.pop()
    address = env[0]
    context = env[1]

    set_context(context)

    if address in flow:
        #print "???"
        continue

    node = None
    for relevant in relevants:
        if relevant.addr == address:
            node = relevant

    block = project.factory.block(address, size=node.size)    
    has_branches = False
    hook_addr = []

    #代码块中有ollvm生成的分支
    for index in range(len(block.capstone.insns)):
        if is_ollvm_branch(index, block.capstone.insns):
            has_branches = True

    #代码块中有ollvm生成的分支
    if has_branches:
        ctx = get_context()
        p1 = find_path(address, 0)
        if p1 != None:
            queue.append((p1, get_context()))
            flow[address].append(p1)

        set_context(ctx)
        p2 = find_path(address, 1)

        if p1 == p2:
            p2 = None

        if p2 != None:
            queue.append((p2, get_context()))
            flow[address].append(p2)
    else:
        p = find_path(address)
        if p != None:
            queue.append((p, get_context()))
            flow[address].append(p)

print('************************flow******************************')
for k, v in flow.items():
    print('%#x: ' % k, [hex(child) for child in v])

print('************************fix******************************')
new_bin = fix(bin)

ins, count = ks.asm("nop")
op_nop_str = "".join([ chr(i) for i in ins])

for node in supergraph.nodes():
    if node not in relevants:
        nop_node = op_nop_str * (node.size / 4)
        new_bin = new_bin[:node.addr-base] + nop_node + new_bin[node.addr-base+node.size:]

with open(new_filename,"wb") as fp:
    fp.write(new_bin)