from cx_Freeze import setup, Executable

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
