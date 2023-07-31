import numpy as np
import warnings
from subprocess import Popen, PIPE
import os
import re

__flag__ = None
__tshark_min_version__ = '2.6.0'
__tshark_max_version__ = '4.0.0'
__tshark_current_version__  = ''
__numpy_min_version__ = '1.18.0'

class Reader(object):
    """Reader object for extracting features from .pcap files

        Attributes
        ----------
        verbose : boolean
            Boolean indicating whether to be verbose in reading
    """

    ########################################################################
    #                         Class initialisation                         #
    ########################################################################

    def __init__(self, verbose=False):
        """Reader object for extracting features from .pcap files

            Parameters
            ----------
            verbose : boolean, default=False
                Boolean indicating whether to be verbose in reading
            """
        # Set verbosity level
        self.verbose = verbose

    ########################################################################
    #                             Read method                              #
    ########################################################################

    def read(self, path,filter="",extension="",ip_layer =False, cmd_parameter = []):
        """Read TCP and UDP packets from .pcap file given by path.
            Parameters
            ----------
            path : string
                Path to .pcap file to read.

            filter : string
                filter condition to be passed to tshark

            extension : string or list (of string)
                Additional field(s) to be extracted, besides the default fields.
                The field name is consistent with that of Wireshark, such as tls.handshake.extension_server_name means the SNI of TLS flow.
                If type(extension) is string, then only one extra field will be extracted.
                If type(extension) is list of string, then multi fileds will be extracted.

            ip_layer : boolean
                Whether parse protocols on ip layer such pptp, l2tp etc.

            Returns
            -------
            result : np.array of shape=(n_packets, n_features)
                Where features consist of:

                0) Filename of capture
                1) Protocol TCP/UDP
                2) TCP/UDP stream identifier
                3) Timestamp of packet
                4) Length of packet
                5) IP packet source
                6) IP packet destination
                7) TCP/UDP packet source port
                8) TCP/UDP packet destination port
                9) Payload length of  TCP/UDP
                10) extension(s)

            Warning
            -------
            warning
                Method throws warning if tshark is not available.
            """

        # If verbose, print which file is currently being read
        if self.verbose:
            print("Reading {}...".format(path))

        # Check if tshark configs well enough
        try:
            if  os.path.exists(path) == False:
                raise FileExistsError('file {0} does not exist.'.format(path))

            if __flag__ == None:
                # Call Tshark on packets
                command = ['tshark','-v']
                try:
                    process = Popen(command, stdout=PIPE, stderr=PIPE)
                    # Get output
                    out, err = process.communicate()
                except :
                    raise  EnvironmentError('tshark is not installed or added to environment path.')
                head = out.decode("utf-8").split('\n')[0].strip()
                version = re.findall('([0-9]+\.[0-9]+\.[0-9]+)',head,re.DOTALL)[0]
                if version < __tshark_min_version__ :
                    raise  EnvironmentError('the version of tshark (wireshark) should be greater than {1} at least, however the current version is {0}.'.format(version,__tshark_min_version__))
                if version > __tshark_max_version__:
                    raise EnvironmentError('the version of tshark (wireshark) should not be greater thant {1}, however the current version if {0}.'.format(version,__tshark_min_version__))
                __tshark_current_version__ = version
                if np.__version__ < __numpy_min_version__ :
                    raise  EnvironmentError('the version of numpy should be greater than {1} at least, however the current version is {0}.'.format(np.__version__ , __numpy_min_version__))

                __flag__ == object()
            return self.read_tshark(path,filter,extension,ip_layer, cmd_parameter)
        except Exception as ex:
            if isinstance(ex,EnvironmentError):
                raise EnvironmentError(ex)
            warnings.warn("Running Error : tshark parse error : '{0}'."
                          .format(ex))

    def read_tshark(self, path,filter_str="",extension="",ip_layer =False, cmd_parameter=[]):
        """Read TCP and UDP packets from file given by path using tshark backend

            Parameters
            ----------
            path : string
                Path to .pcap file to read.

            Returns
            -------
            result : np.array of shape=(n_packets, n_features)
                Where features consist of:
                0) Filename of capture
                1) Protocol TCP/UDP
                2) TCP/UDP stream identifier
                3) Timestamp of packet
                4) Length of packet
                5) IP packet source
                6) IP packet destination
                7) TCP/UDP packet source port
                8) TCP/UDP packet destination port
                9) Payload length
                10) extension fields
            """
        # Create Tshark command
        if ip_layer == False:
            command = ["tshark", "-r", path, "-Tfields", "-E", "separator=`",
                   "-e", "frame.time_epoch",
                   "-e", "tcp.stream",
                   "-e", "udp.stream", #only output one line
                   "-e", "ip.proto",
                   "-e", "ipv6.nxt",  ##only output one line,
                   "-e", "ip.src",
                   "-e", "ipv6.src",    #only output one line,
                   "-e", "tcp.srcport",
                   "-e", "udp.srcport", #only output one line
                   "-e", "ip.dst",
                   "-e", "ipv6.dst",    #only output one line
                   "-e", "tcp.dstport",
                   "-e", "udp.dstport", #only output one line
                   "-e", "ip.len",
                   "-e", "ipv6.plen",
                   '-e', "tcp.len",
                   "-e", "udp.length",   #only output one line,
                   "-e", 'ip.id',
                   "-2","-R", "ip or ipv6 and not icmp and not tcp.analysis.retransmission and not mdns and not ssdp{0}"]
        else:
            command = ["tshark", "-r", path, "-Tfields", "-E", "separator=`",
                   "-e", "frame.time_epoch",
                   "-e", "tcp.stream",
                   "-e", "udp.stream", #only output one line
                   "-e", "ip.proto",
                   "-e", "ipv6.nxt",  ##only output one line,
                   "-e", "ip.src",
                   "-e", "ipv6.src",    #only output one line,
                   "-e", "tcp.srcport",
                   "-e", "udp.srcport", #only output one line
                   "-e", "ip.dst",
                   "-e", "ipv6.dst",    #only output one line
                   "-e", "tcp.dstport",
                   "-e", "udp.dstport", #only output one line
                   "-e", "ip.len",
                   "-e", "ipv6.plen",
                   '-e', "tcp.len",
                   "-e", "udp.length",   #only output one line,
                   "-e", 'ip.id',
                   "-2","-R", "ip or ipv6 and not icmp{0}"]

        if filter_str != "":
            command[-1] = command[-1].format(" and "+filter_str)
        else:
            command[-1] = command[-1].format("")

        #Add extended protocols

        #Add extension fields
        if type(extension) == type(""):
            extension  = [extension]
        extension =['_ws.col.Protocol'] + extension
        for each in extension:
            if each != "" :
                if each in command :
                    raise ValueError('The extension field `{0}` has been extracted more than once at least! Please check your extension parameter!'.format(each))
                command.insert(-5,'-e')
                command.insert(-5,each)
        #print(" ".join(command))
        # Initialise result
        if len(cmd_parameter)>0 :
            command+= cmd_parameter

        result = list()

        # Call Tshark on packets
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        # Get output
        out, err = process.communicate()

        # Give warning message if any
        if err:
            warnings.warn("Error reading file: '{}'".format(
                err.decode('utf-8')))
        protocols = {'17': 'udp', '6': 'tcp','47':'gre'}
        # Read each packet
        for packet in filter(None, out.decode('utf-8',errors="ignore").split('\n')):
            # Get all data from packets
            packet = packet.strip()
            packet = packet.split('`')
            #print(len(packet), packet)
            if len(packet) < 18:
                continue

            # Perform check on multiple ip addresses
            protocol = protocols.get(packet[3],'unknown') if packet[3]!='' else protocols.get(packet[4],'unknown')
            ip_src = packet[5].split(',')[0] if packet[5].split(',')[0]!= '' else packet[6].split(',')[0]            #ip.src
            ip_dst = packet[9].split(',')[0] if packet[9].split(',')[0]!= '' else packet[10].split(',')[0]       #ip.dst
            ip_len = packet[13].replace(',', '')  if  packet[13].replace(',', '')!='' else  packet[14].replace(',', '')      #ip.len
            #if packet[2]=='udp':
            #    print('#' * 10)
            #    print(packet)

            # Add packet to result
            #路径|tcp(udp)|flowid|时间戳|IP长度|srcIP|dstIP|srcport|dstport|payload长度|extension|
            timestamp=packet[0]
            ext_protocol = packet[17]
            extension = packet[18:-1]

            if protocol in ['tcp','udp'] and ip_layer == False:
                flowid = packet[1] if protocol=='tcp' else packet[2]
                srcport = packet[7] if protocol=='tcp' else packet[8]
                dstport = packet[11] if protocol=='tcp' else packet[12]
                payload_length = packet[15] if protocol =='tcp' else packet[16]
            else:
                flowid = 0
                srcport = 1
                dstport = 0
                payload_length = 0
            result.append([path]+[(protocol,ext_protocol), flowid, timestamp, ip_len, ip_src, ip_dst, srcport, dstport,payload_length, extension])
        # Get result as numpy array

        result = np.asarray(result, dtype=object)

        # Check if any items exist
        if not result.shape[0]:
            return np.zeros((0, 12+len(extension)), dtype=object)

        # Change protocol number to text

        #print(result.shape)
        #print(result[0:2, [0, 3, 2, 1, 8, 4, 6, 5, 7, 9,10]])
        # Return in original order

        return result
