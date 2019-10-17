#coding=utf-8

from capstone import *
from capstone.arm import *

	
offset = 0x11D94 #function start
end = 0x14CF8    #function end

bin = open('libdynamicMono.so','rb').read()
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True #enable detail analyise
    

for i in md.disasm(bin[offset:end], offset):      
    print "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str) 
    for op in i.operands:
        if op.type == ARM_OP_IMM and op.value.imm == i.address:
                print "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str) 
                
