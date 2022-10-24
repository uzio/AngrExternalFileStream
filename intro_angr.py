#!usr/local/bin/python
#encoding: utf-8
import sys
import angr
import claripy
from angrutils import *

reload(sys) # NOTE python2
sys.setdefaultencoding('utf-8')

def main():
    proj = angr.Project('./introduction')

    ### step 1 获取CFG，找到目标 ###

    # cfg = proj.analyses.CFGFast(show_progressbar=True)
    # for addr,func in proj.kb.functions.items():
    #     if func.name == 'main':
    #         plot_cfg(cfg, "./intro_static_cfg", asminst=True, vexinst=False, func_addr={addr:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)

### step 2 符号执行 ###
    state = proj.factory.entry_state()

    system_address =0x40130f
    
    simulation = proj.factory.simgr(state)
    simulation.explore(find=system_address)
    if simulation.found:   
        solution_state = simulation.found[0]
        print(solution_state.posix.dumps(sys.stdin.fileno())) 


if __name__ == '__main__':
    main()