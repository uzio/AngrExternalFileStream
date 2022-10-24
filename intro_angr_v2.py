#!usr/local/bin/python
#encoding: utf-8
import sys
import angr
import claripy
from angrutils import *

reload(sys) # NOTE python2
sys.setdefaultencoding('utf-8')

def main():
    if len(sys.argv)>1:
        _get_cfg = sys.argv[1] # 可选绘制CFG
    else:
        _get_cfg = 0
    
    if len(sys.argv)>2:
        _func = sys.argv[2] # 可选绘制起始函数块
    else:
        _func = 'main'

    proj = angr.Project('./introduction_b')

    ### step 1 获取CFG，找到目标 ###
    if _get_cfg == '1':
        cfg = proj.analyses.CFGFast(show_progressbar=True)
        for addr,func in proj.kb.functions.items():
            if func.name == _func: # 函数名
                plot_cfg(cfg, "./intro_static_cfg", asminst=True, vexinst=False, func_addr={addr:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)

    ### step 2 符号执行 ###
    state = proj.factory.entry_state()

    # system_address =0x40130f
    _addr_u =0x4011e8
    _addr_p =0x4011ff

    

    simulation = proj.factory.simgr(state)
    simulation.explore(find=_addr_u)
    if simulation.found:   
        solution_state = simulation.found[0]
        print(solution_state.posix.dumps(sys.stdin.fileno())) 
    print('~~~')
    simulation = proj.factory.simgr(state)
    simulation.explore(find=_addr_p)
    if simulation.found:   
        solution_state = simulation.found[0]
        print(solution_state.posix.dumps(sys.stdin.fileno())) 

if __name__ == '__main__':
    main()