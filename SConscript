# RT-Thread building script for bridge

from building import *

cwd      = GetCurrentDir()
src      = Glob('src/*.c')

CPPPATH  = [cwd + '/inc']

group = DefineGroup('agile_ftp', src, depend = ['PKG_USING_AGILE_FTP'], CPPPATH = CPPPATH)

Return('group')
