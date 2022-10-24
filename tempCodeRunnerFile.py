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