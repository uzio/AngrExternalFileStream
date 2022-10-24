#! /usr/bin/env
# encoding : utf-8

import os
import sys
import angr
import claripy
from angr.storage import SimFile

def get_containts(filepath):
    '''
    从文件中读取约束条件
    '''
    constraints = []
    with open(filepath,'r') as f:
        if not os.path.exists(filepath):
            raise Exception('containts data not exist.')
        lines = f.readlines()
        f.close()
    for line in lines:
        constraints.append(line.replace('\n',''))
    return constraints

def main(argv):
    abspath = os.path.abspath(os.path.dirname(__file__))
    path_to_binary = abspath + '/intro_2'
    p = angr.Project(path_to_binary)

    _usr = claripy.BVS('aUsr',2*8) # 用户名
    _pwd = claripy.BVS('aPwd',2*8) # 密码

    start_addr = 0x40148a # auth函数入口
    # init_state = p.factory.call_state(start_addr, _usr,_pwd)
    init_state = p.factory.blank_state(addr=start_addr)

    # constraints = get_containts('./verify.txt')
    constraints = get_containts(abspath + '/verify.txt') # NOTE 读取用户验证数据（来源：文本/数据库）

    ## XXX 用户验证数据文件的创建准备 
    #
    filename = 'verify.txt'
    symbolic_file_size_bytes = 0x05 # TODO 自动计算所需文件流的字节数
    #
    temp = (constraints[0] + '\n' + constraints[1] ).encode('utf-8') # TODO 自动格式化组合所有数据
    c_ver = claripy.BVV(temp,symbolic_file_size_bytes*8)  
    ##
    sim_file = SimFile(filename, content=c_ver, size=symbolic_file_size_bytes) # NOTE 使用读取到的数据创建模拟文件流

    init_state.fs.insert(filename,sim_file) # 将模拟文件流插入到angr的模拟文件系统

    @p.hook(addr=0x401355,length=2) # 跳过目的无关的循环
    def jmp(state):
        state.regs.rip = 0x401374

    @p.hook(addr=0x40131e,length=5) # XXX 替换字符串比较strcmp，同时解析文件流以获取约束条件 usr ? 'GO'
    def strcmp_u(state):
        ct_usr = state.solver.eval(state.memory.load(state.regs.rsi,8), cast_to=bytes).decode('utf-8').strip().strip(b'\x00'.decode()).encode('utf-8')
        state.regs.eax = claripy.If(
            _usr == ct_usr,
            claripy.BVV(0,32),
            claripy.BVV(1,32)
        )
    @p.hook(addr=0x401338,length=5) # XXX 替换字符串比较strcmp，同时解析文件流以获取约束条件 pwd ? 'ON'
    def strcmp_p(state):
        ct_pwd = state.solver.eval(state.memory.load(state.regs.rsi,8), cast_to=bytes).decode('utf-8').strip().strip(b'\x00'.decode()).encode('utf-8')
        state.regs.eax = claripy.If(
            _pwd == ct_pwd,
            claripy.BVV(0,32),
            claripy.BVV(1,32)
        )

    sm = p.factory.simgr(init_state)

    def is_good(state):
        return b'Command' in state.posix.dumps(sys.stdout.fileno()) # NOTE 该输出状态说明程序成功进入后门，等待指令输入

    def is_bad(state):
        return b'Verification failed' in state.posix.dumps(sys.stdout.fileno()) # 验证失败的输出状态
    
    sm.explore(find=is_good,avoid=is_bad)
    # sm.explore(find=0x401341, avoid=0x40134b)

    if sm.found:
        check_state = sm.found[0]
        username = check_state.solver.eval(_usr, cast_to=bytes).decode('utf-8','ignore')
        password = check_state.solver.eval(_pwd, cast_to=bytes).decode('utf-8','ignore')
        print("Solution found > username:{} , password:{}".format(username,password))
    else:
        raise Exception("Solution not found")

if __name__ == '__main__':
    main(sys.argv)