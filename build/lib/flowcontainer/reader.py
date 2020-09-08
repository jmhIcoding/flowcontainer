from cryptography import x509
from cryptography.hazmat.backends import default_backend
import glob
import numpy as np
import os
import pyshark
import warnings
from subprocess import Popen, PIPE

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

    def read(self, path):
        """Read TCP and UDP packets from .pcap file given by path.
            Automatically choses fastest available backend to use.

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
                10) TCP length
                11) UDP length
                9) SSL/TLS Server Name Identification if exists, else ""

            Warning
            -------
            warning
                Method throws warning if tshark is not available.
            """

        # If verbose, print which file is currently being read
        if self.verbose:
            print("Reading {}...".format(path))

        # Check if we can use fast tshark read or slow pyshark read
        try:
            return self.read_tshark(path)
        except Exception as ex:
            warnings.warn("tshark error: '{}', defaulting to pyshark backend. "
                          "note that the pyshark backend is much slower than "
                          "the tshark backend."
                          .format(ex))
            raise ex


    def read_tshark(self, path):
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
                9) SSL/TLS certificate if exists, else None
                10) TCP length
                11) UDP length
            """
        # Create Tshark command
        command = ["tshark", "-r", path, "-Tfields",
                   "-e", "frame.time_epoch",
                   "-e", "tcp.stream",
                   "-e", "udp.stream", #only output one line
                   "-e", "ip.proto",
                   "-e", "ip.src",
                   "-e", "tcp.srcport",
                   "-e", "udp.srcport", #only output one line
                   "-e", "ip.dst",
                   "-e", "tcp.dstport",
                   "-e", "udp.dstport", #only output one line
                   "-e", "ip.len",
                   '-e', "tcp.len",
                   "-e", "udp.length",  #only output one line
                   "-e", "tls.handshake.extensions_server_name",
                   "-2","-R", "ip and not icmp and  not tcp.analysis.retransmission and not tcp.analysis.out_of_order and not tcp.analysis.duplicate_ack and not mdns and not ssdp"]
        # Initialise result
        result = list()

        # Call Tshark on packets
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        # Get output
        out, err = process.communicate()

        # Give warning message if any
        if err:
            warnings.warn("Error reading file: '{}'".format(
                err.decode('utf-8')))
        protocols = {'17': 'udp', '6': 'tcp'}
        # Read each packet
        for packet in filter(None, out.decode('utf-8').split('\n')):
            # Get all data from packets
            packet = packet.split()
            #example: ['1592995818.017318000', '0', '6', '192.168.0.100', '49924', '23.51.209.190', '80', '60', '0']
            #input()
            # Perform check on packets
            #print(packet)
            if len(packet) < 9: continue

            # Perform check on multiple ip addresses
            packet[2] = protocols.get(packet[2],'unknown')
            packet[3] = packet[3].split(',')[0]         #ip.src
            packet[5] = packet[5].split(',')[0]         #ip.dst
            packet[7] = packet[7].replace(',', '')      #ip.len
            #if packet[2]=='udp':
            #    print('#' * 10)
            #    print(packet)
            if len(packet) == 9:
                packet.append("")

            # Add packet to result

            result.append([path] + packet)

            #print(result[-1])

        # Get result as numpy array

        result = np.asarray(result)

        # Check if any items exist
        if not result.shape[0]:
            return np.zeros((0, 10), dtype=object)

        # Change protocol number to text

        #print(result.shape)
        #print(result[0:2, [0, 3, 2, 1, 8, 4, 6, 5, 7, 9,10]])
        # Return in original order
        return result[:, [0, 3, 2, 1, 8, 4, 6, 5, 7, 9,10]]
