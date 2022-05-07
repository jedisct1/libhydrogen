from building import *

if GetDepend('PKG_USING_LIBHYDROGEN'):
    Import('RTT_ROOT')
    Import('rtconfig')

    objs    = []
    cwd     = GetCurrentDir()

    src     = 'hydrogen.c'
    path    = [cwd]

    group   = DefineGroup('libhydrogen', src, depend = ['PKG_USING_LIBHYDROGEN'], CPPPATH = path)

    Return('group')

else:
    print('The scons script only supports RT-Thread, please use Makefiles/zig/cmake.')