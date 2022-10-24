#!usr/local/bin/python3
#encoding: utf-8
import sys
import angr
from angrutils import *

proj = angr.Project('/home/uzio/pythonTestCode/Draft/intro/introduction', auto_load_libs=False) 

cfg = proj.analyses.CFGFast()

print(">The static CFG has %d nodes and %d edges." % (len(cfg.graph.nodes()), len(cfg.graph.edges())))
for addr,func in proj.kb.functions.items():
    with open("intro.txt","a") as f:
        f.write('addr=%x,func=%s'%(addr,func))
    if func.name == 'auth':#'main':
        plot_cfg(cfg, "./intro_auth_cfg", asminst=True, vexinst=False, func_addr={addr:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)

print ('end')