#coding:utf8
__author__ = 'dk'
import setuptools
long_desp = ""
with open("README.md","r") as fp:
    long_desp = fp.read()
setuptools.setup(
    name="flowcontainer",
    version="1.2",
    author="Jiang Minghao",
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
