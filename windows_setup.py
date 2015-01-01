from cx_Freeze import setup, Executable
import shutil
import os

# Dependencies are automatically detected, but it might need
# fine tuning.
buildOptions = dict(packages = ["dns"], excludes = [], include_files = ['resolvers.txt', 'names.txt', 'LICENSE'])

executables = [
    Executable('subbrute.py', 'Console')
]

setup(name='SubBrute',
      version = '1.1',
      description = 'A fast and accurate subdomain enumeration tool.',
      options = dict(build_exe = buildOptions),
      executables = executables)

#copy from the build directory to ./windows/
src = "build\\exe.win32-3.4\\"
dest = "windows"
src_files = os.listdir(src)
for file_name in src_files:
    full_file_name = os.path.join(src, file_name)
    if (os.path.isfile(full_file_name)):
        shutil.copy(full_file_name, dest)