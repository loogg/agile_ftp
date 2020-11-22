from building import *
import rtconfig

src = Glob('src/*.c')
cwd = GetCurrentDir()
CPPPATH = [cwd + '/inc']

group = DefineGroup('FTP', src, depend = [''], CPPPATH=CPPPATH)

Return('group')
