__author__ = 'dk'
### split large pcap file into smaller pieces according to the 5-tuples
import time
from subprocess import Popen, PIPE
import os, shutil, platform

def check_environment():
    command = ['splitpcap','-v']
    try:
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        # Get output
        out, err = process.communicate()
    except :
        raise  EnvironmentError('splitpcap is not installed or added to environment path. Please access https://github.com/jmhIcoding/splitpcap for help!')

    command = ['editcap','-v']
    try:
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        # Get output
        out, err = process.communicate()
    except :
        raise  EnvironmentError('tshark is not installed or added to environment path. Please access https://www.netresec.com/?page=SplitCap for help!')


def split_cap(infile):
    check_environment()
    if platform.system() == 'Windows':
        dirs = "{0}\\__splitcap__\\{1}_{2}\\".format(os.path.realpath(os.path.curdir),os.path.basename(infile), int(time.time()))
    else:
        dirs = "{0}/__splitcap__/{1}_{2}/".format(os.path.realpath(os.path.curdir),os.path.basename(infile), int(time.time()))
    os.makedirs(dirs)
    # first, convert the format of the source pcap file into normal pcap, as the source format might be pcapng, etc...
    convert_cmd = "editcap -F pcap {0} {1}".format(infile, infile + ".pcap")
    os.system(convert_cmd)
    infile = infile + '.pcap'
    split_cmd = "splitpcap {0} {1} 20".format(infile, dirs)
    os.system(split_cmd)
    os.remove(infile)
    return dirs
if __name__ == '__main__':
    dirs = split_cap(r'C:\Users\dk\Documents\flowcontainer\huajiaozhibo.pcapng')
    print(dirs)