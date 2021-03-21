#coding:utf8
__author__ = 'dk'
import setuptools
long_desp = \
'''
A python lib to parse traffic flow information from pcaps.\n
Homepage : https://github.com/jmhIcoding/flowcontainer.\n
Fix bugs:\n
\t set the default filter string to be `tcp or udp or gre`.\n
\t update help information for errors. \n
'''

setuptools.setup(
    name="flowcontainer",
    version="3.14",
    author="Minghao Jiang",
    author_email="jiangminghao@iie.ac.cn",
    description="A python lib to parse traffic flow information from pcaps",
    url="https://github.com/jmhIcoding/flowcontainer",
    long_description=long_desp,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
