# encoding : utf-8

import os
import sys
import angr
import claripy
import logging
from angr.storage import SimFile
from functools import reduce

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

def main(argv, usr_len, pwd_len):
    # path_to_binary = sys.argv[1]
    # path_to_binary = '/home/uzio/pythonTestCode/Draft/intro/intro_2'
    abspath = os.path.abspath(os.path.dirname(__file__))
    path_to_binary = abspath + '/intro_2'
    p = angr.Project(path_to_binary)

    _usr = claripy.BVS('aUsr',usr_len*8) # 用户名 XXX 需要给出正确位数，否则无法得到解
    _pwd = claripy.BVS('aPwd',pwd_len*8) # 密码 XXX 需要给出正确位数，否则无法得到解

    start_addr = 0x40148a # auth函数入口
    # init_state = p.factory.call_state(start_addr, _usr,_pwd)
    init_state = p.factory.blank_state(addr=start_addr)

    filepath=init_state.solver.eval(init_state.memory.load(0x401216+0xdf0,30), cast_to=bytes).decode('utf-8').split('\x00')[0] # XXX cfg图中filename保存地址：rip+0xdf0，而rip=下条语句地址

    # constraints = get_containts('./verify.txt')
    # constraints = get_containts('/home/uzio/pythonTestCode/Draft/intro/verify.txt') 
    # constraints = get_containts(abspath + '/' + filepath) # NOTE 读取用户验证数据（来源：文本/数据库）

    # ## NOTE 用户验证数据文件的创建准备 
    # #
    # filename = 'verify.txt'
    
    # # tol_cons = (constraints[0] + '\n' + constraints[1] ).encode('utf-8')
    # tol_cons = reduce(lambda x, y: x+'\n'+y, constraints[1:], constraints[0]).encode('utf-8') # NOTE 自动格式化组合所有数据
    # # symbolic_file_size_bytes = 0x05
    # symbolic_file_size_bytes = len(tol_cons) # NOTE 自适应所需文件流的字节数
    # #
    # c_ver = claripy.BVV(tol_cons,symbolic_file_size_bytes*8)  
    # ##
    # sim_file = SimFile(filename, content=c_ver, size=symbolic_file_size_bytes) # NOTE 使用读取到的数据创建模拟文件流

    # init_state.fs.insert(filename,sim_file) # 将模拟文件流插入到angr的模拟文件系统

    @p.hook(addr=0x401355,length=2) # 跳过目的无关的循环
    def jmp(state):
        state.regs.rip = 0x401374 # 直接跳转

    # @p.hook(addr=0x40131e,length=5) # XXX 替换字符串比较strcmp，同时解析文件流以获取约束条件 usr ? con[0]
    # def strcmp_u(state):
    #     ct_usr = state.solver.eval(state.memory.load(state.regs.rsi,8), cast_to=bytes).decode('utf-8').strip().strip(b'\x00'.decode()).encode('utf-8') # XXX 当字长超过阈值时，需要修改内存的读取范围
    #     logging.warn('constraint for username : %s'%ct_usr)
    #     state.regs.eax = claripy.If(
    #         _usr == ct_usr,
    #         claripy.BVV(0,32),
    #         claripy.BVV(1,32)
    #     )
    # @p.hook(addr=0x401338,length=5) # XXX 替换字符串比较strcmp，同时解析文件流以获取约束条件 pwd ? con[1]
    # def strcmp_p(state):
    #     ct_pwd = state.solver.eval(state.memory.load(state.regs.rsi,8), cast_to=bytes).decode('utf-8').strip().strip(b'\x00'.decode()).encode('utf-8') # XXX 当字长超过阈值时，需要修改内存的读取范围
    #     logging.warn('constraint for password: %s'%ct_pwd)
    #     state.regs.eax = claripy.If(
    #         _pwd == ct_pwd,
    #         claripy.BVV(0,32),
    #         claripy.BVV(1,32)
    #     )

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
    lusr = int(input('用户名长度? :'))
    lpwd = int(input('密码长度? :'))
    main(sys.argv, lusr, lpwd)