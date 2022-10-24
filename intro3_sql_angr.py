# encoding : utf-8
import logging
import os
import sys
import angr
import claripy
import pymysql
from angrutils.visualize import plot_cfg

## MySQL ##
def getConnection(host, port, db, user, passwd):
    '''
    MySQL 连接
    '''
    conn = pymysql.connect(host=host, port=port, db=db, user=user, password=passwd)
    return conn

def getData(_conn, sql):
    '''
    MySQL 数据获取
    '''
    conn = _conn
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute(sql)

    dataSet = cursor.fetchone()

    data =[]
    for k in dataSet:
        data.append(dataSet[k])

    cursor.close()
    conn.close()
    
    return data

###
# main #
###
def main(argv, usr_len, pwd_len):
    abspath = os.path.abspath(os.path.dirname(__file__))
    path_to_binary = abspath + '/intro3_sql'

    base = 0xe000000
    p = angr.Project(path_to_binary, load_options={ 
        'main_opts' : { 
            'base_addr' : base
        } 
    } )

    start_addr = base +0x145c
    init_state = p.factory.blank_state(addr=start_addr)

    global _contraints
    _contraints = []
    _usr = claripy.BVS('aUsr',usr_len*8) # 用户名 XXX 需要给出正确位数，否则无法得到解
    _pwd = claripy.BVS('aPwd',pwd_len*8) # 密码 XXX 需要给出正确位数，否则无法得到解

    ##MySQL 相关参数##
    host = init_state.solver.eval(init_state.memory.load(base+0x1309 + 0xd20, 20), cast_to=bytes).decode('utf-8','ignore').split('\x00')[0]
    user = init_state.solver.eval(init_state.memory.load(base+0x1302 + 0xd19, 20), cast_to=bytes).decode('utf-8','ignore').split('\x00')[0]
    passwd = init_state.solver.eval(init_state.memory.load(base+0x12fb + 0xd25, 20), cast_to=bytes).decode('utf-8','ignore').split('\x00')[0]
    db = init_state.solver.eval(init_state.memory.load(base+0x12f4 + 0xd27, 20), cast_to=bytes).decode('utf-8','ignore').split('\x00')[0]
    port = 3306 # NOTE default


    sql = init_state.solver.eval(init_state.memory.load(base+0x1341+0xd17, 100), cast_to=bytes).decode('utf-8','ignore').split('\x00')[0]

    logging.warn("host->{},user->{},pwd->{},db->{}".format(host,user,passwd,db))
    logging.warn("sql : {}".format(sql))

    conn = getConnection(host=host, port=port, db=db, user=user, passwd=passwd)
    if(conn):
        logging.info("Connected.")
        _contraints = getData(_conn=conn, sql=sql)
    else:
        raise Exception("MySQL connection failed.")
    ##
    
    if(len(argv)>1 and argv[1] in ['Yes', 'yes', 'y', 'Y']):
        _func = input("要绘制哪个函数的CFG图？:")
        if _func is None:
            _func = 'main'
        cfg = p.analyses.CFGFast(show_progressbar=True)
        for addr,func in p.kb.functions.items():
            if func.name == _func:
                plot_cfg(cfg, './cfg/intro3_%s_cfg'%_func, asminst=True, vexinst=False, func_addr={addr:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)

    @p.hook(addr=base+0x146a,length=5)
    def strcmp(state):
            c_usr = _contraints[0].encode('utf-8')
            state.regs.eax = claripy.If(
            _usr == c_usr,
            claripy.BVV(0,32),
            claripy.BVV(1,32)
        )

    @p.hook(addr=base+0x1481,length=5)
    def strcmp(state):
            c_pwd = _contraints[1].encode('utf-8')
            state.regs.eax = claripy.If(
            _pwd == c_pwd,
            claripy.BVV(0,32),
            claripy.BVV(1,32)
        )
    
    sm = p.factory.simgr(init_state)

    def is_good(state):
        return b'Command' in state.posix.dumps(sys.stdout.fileno()) # NOTE 该输出状态说明程序成功进入后门，等待指令输入

    def is_bad(state):
        return b'Verification failed' in state.posix.dumps(sys.stdout.fileno()) # 验证失败的输出状态
    
    # sm.explore(find=is_good,avoid=is_bad)
    sm.explore(find=base+0x148a,avoid=base+0x1494)

    if sm.found:
        check_state = sm.found[0]
        username = check_state.solver.eval(_usr, cast_to=bytes).decode('utf-8','ignore')
        password = check_state.solver.eval(_pwd, cast_to=bytes).decode('utf-8','ignore')
        print("Solution found > username:{} , password:{}".format(username,password))
    else:
        raise Exception("Solution not found")

if __name__ == '__main__':
    # lusr = int(input('用户名长度? :'))
    # lpwd = int(input('密码长度? :'))
    lusr = 5
    lpwd = 7
    main(sys.argv, lusr, lpwd)