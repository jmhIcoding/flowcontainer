__author__ = 'dk'
from flowcontainer.reader import Reader
from flowcontainer.flow_generator import FlowGenerator
import os, shutil
from flowcontainer import split_pcap
import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

MB =  1024 * 1024
__split_pcap_threshold = 100* MB

def real_extract(infile, filter, extension, ip_layer,cmd_parameter, verbose):
    reader = Reader(verbose=False)
    flow_generator = FlowGenerator()
    # Read packets
    result = reader.read(infile,filter,extension,ip_layer,cmd_parameter=cmd_parameter)
    # Combine packets into flows
    result = flow_generator.combine(result,extension)
    # Return result
    return result
def extract(infile,filter="(tcp or udp or gre)",extension="", ip_layer=False, verbose=True, cmd_parameter=[], split_flag=False):
    """Extract flows from given pcap file.

        Parameters
        ----------
        infile : string
            Path to input file.
        filter : string
            Filter condition, which is the same with wireshark
        extension : string or (list of string)
            Additional field(s) to be extracted, besides the default fields.
            The field name is consistent with that of Wireshark, such as tls.handshake.extension_server_name means the SNI of TLS flow.
            If type(extension) is string, then only one extra field will be extracted.
            If type(extension) is list of string, then multi fileds will be extracted.

        split_flag: bool
            if True, split the large pcap into smaller pieces.

        Returns
        -------
        result : dict
            Dictionary of flow_key -> flow.
        """
    if type(extension)==type(""):
        extension = [extension]

    for each in extension:
        if type(each)!= type(""):
            raise TypeError("extension must be string!")

    # Check if the pcap exist?
    assert os.path.exists(infile) == True
    fstat = os.stat(infile)
    if split_flag == True  and fstat.st_size > __split_pcap_threshold:
        dirs = split_pcap.split_cap(infile)
        files = []
        for _root, _dirs, _files in os.walk(dirs):

            for file in _files:
                files.append(_root+'/'+ file)
        ### 创建线程依次解析各个pcap
        thread_pool = ThreadPoolExecutor(max_workers=20)
        tasks = []
        for file in files:
            tasks.append(thread_pool.submit(real_extract,file, filter, extension, ip_layer, cmd_parameter, verbose))

        result = {}

        for task in as_completed(tasks):
            #print(task)
            result.update(task.result())
        shutil.rmtree(path=dirs, ignore_errors=True)

    else:
        result = real_extract(infile,filter,extension, ip_layer, cmd_parameter, verbose)

    return result