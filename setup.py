#!/usr/bin/env python
import os
from setuptools import setup, find_packages


long_description = open(
    os.path.join(
        os.path.dirname(__file__),
        'README.md'
    )
).read()


setup(
    name='SubBrute',
    version='2.0',
    license='LICENSE',
    url='https://github.com/TheRook/subbrute',
    description='A fast and accurate subdomain enumeration tool.',
    long_description=long_description,
    packages=find_packages('.', exclude=["dnslib", "*.tests", "*.tests.*", "tests.*", "tests"]),
    py_modules=["subbrute"],
    data_files=[('', ['names.txt', 'resolvers.txt', 'names_small.txt'])],
    install_requires=['dnslib'],
    entry_points={
        'console_scripts': [
            'subbrute = subbrute:main',
        ]
    },
    keywords=['dns', 'subdomain', 'spider']
)
