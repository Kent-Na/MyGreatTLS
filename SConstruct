compile_source_message = '\033[34mCompiling > \033[0m$SOURCE'
link_program_message = '\033[35mLinking > \033[0m$TARGET'

env = Environment(
	CXXCOMSTR = compile_source_message,
	CCCOMSTR = compile_source_message,
	LINKCOMSTR = link_program_message,
	ARCOMSTR = link_program_message,
	RUNLIBCOMSTR = link_program_message,
)

#env.Append(CCFLAGS = ['-O3'])
env.Replace(CC = 'clang')
env.Replace(CXX = 'clang++')
#env.Replace(OBJCC = 'clang')
#env.Replace(OBJCXX = 'clang++')
#env.Replace(CC = 'gcc')
#env.Replace(CXX = 'g++')
env.Append(CCFLAGS = ['-Wall','-g'])
#env.Append(CCFLAGS = ['-Wall','-g','-O3'])

cflags = [
	'-fcolor-diagnostics',
	'-Wno-pointer-sign',
	'-Wno-deprecated-declarations',
	'-Wno-narrowing',
	'-Wno-unused']

#env.Append(CFLAGS = 
env.Append(CCFLAGS = cflags)
env.Append(CXXFLAGS = cflags)
#env.Append(CXXFLAGS = ['-stdlib=libc++'])
env.Append(CXXFLAGS = ['-std=c++11'])
env.Append(LIBS = ['c++abi', 'c++'])
env.Append(LIBS = ['crypto', 'ssl'])

Export('env')

SConscript('SConscript', variant_dir='build', duplicate=0)

