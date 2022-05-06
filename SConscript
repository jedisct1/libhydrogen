Import('RTT_ROOT')
Import('rtconfig')
from building import *

objs = []
cwd     = GetCurrentDir()

src     = 'hydrogen.c'
path   =  [cwd]

group = DefineGroup('libhydrogen', src, depend = ['PKG_USING_LIBHYDROGEN'], CPPPATH = path)

Return('group')
