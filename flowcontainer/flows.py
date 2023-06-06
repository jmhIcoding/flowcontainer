from datetime import datetime
import ipaddress

################################################################################
#                              Single Flow object                              #
################################################################################

class Flow(object):
    """Flow object extracted from pcap file that can be used for fingerprinting

        Attributes
        ----------
        src : string
            Source IP

        sport : int
            Source port

        dst : string
            Destination IP

        dport : int
            Destination port

        source : tuple
            (Source IP, source port) tuple

        destination : tuple
            (Destination IP, destination port) tuple

        time_start : int
            Timestamp of first packet in flow

        time_end : int
            Timestamp of last packet in flow

        ip_lengths : list
            List of packet length for each ip packet in flow

        payload_lengths : list
            List of payload sequence for each tcp/udp fragment with non-zero payload in flow.

        ip_timestamps : list
            List of timestamps corresponding to each ip packet in flow, it may contain packets without any tcp/udp payload.

        payload_timestamps: list
            List of timestamps corresponding to each tcp/udp fragment with non-zero payload in flow.

        extension : dict
            Dict of extension, where the keys are items which are passed through flowcontainer.extractor.extract functions.
            the values `extension[key]` are list of tuple, where each tuple is (value,packet_id).
    """

    def __init__(self,main='payload'):
        """
            param
            -----------
            main: str
              'payload' means the main lengths sequence and timestampes sequence refer to packets with non-zero payload, the sequences will fitler out zero payload packets.
              'ip'   means the main lengths sequence and timestamps sequence refer to any packets, it will not filter any packets.
        """
        self.main = main
        """Initialise an empty Flow."""
        # Initialise flow endpoints
        self.src   = None
        self.sport = None
        self.dst   = None
        self.dport = None
        self.protocol = None
        self._ext_protocols = set()
        # Initialise extension
        self.extension = dict()
        # Initialise packet lengths
        self.ip_lengths   = list()
        self.payload_lengths = list()
        # Initialise packet timestamps
        self.ip_timestamps = list()
        self.payload_timestamps = list()   #non-zero payload packet's timestamp sequence.

        # Refer the main property
        self.lengths = self.payload_lengths if main=='payload' else self.ip_lengths
        self.timestamps = self.payload_timestamps if main=='payload' else self.ip_timestamps
    ########################################################################
    #                        Add new packet to flow                        #
    ########################################################################

    def add(self, packet,extension):
        """Add a new packet to the flow.

            Parameters
            ----------
            packet : np.array of shape=(n_features,)
                Packet from Reader.

            Returns
            -------
            self : self
                Returns self
            """
        #print(packet)
        try:
            # Extract IPs from packet
            ip_a, ip_b = packet[5], packet[6]
        except BaseException as exp:
            raise ValueError('Parse ip address error, this is not ip packet! Please pass the filter parameter with `(tcp or udp)` when invoke flowcontainer.extractor.extract()!')
        try:
            # Extract ports from packet
            port_a, port_b = int(packet[7]), int(packet[8])
        except BaseException as exp:
            raise ValueError('Parse TCP/UDP port error, this ip packet may not be a sample of tcp or udp or gre. Please pass the filter parameter with `(tcp or udp)` when invoke flowcontainer.extractor.extract()!')
        # Perform packet check
        if self.src is not None:
            if {self.src, self.dst} != {ip_a, ip_b} and {self.sport, self.dport} != {port_a, port_b}:
                print("Packet {} incompatible with flow {}" .format(packet, self))
        # Set endpoints where smallest dport is destination
        elif port_a > port_b:
            self.src  , self.dst   = ip_a  , ip_b
            self.sport, self.dport = port_a, port_b
        else:
            self.src  , self.dst   = ip_b  , ip_a
            self.sport, self.dport = port_b, port_a
        if self.protocol is None:
            self.protocol = packet[1][0]
        self._ext_protocols.add(packet[1][1])
        # Add extension if any
        if len(packet[-1]) > len(extension):
            ## means the separate "`" exists in the payload...
            packet[-1][-1] = "`".join(packet[-1][len(extension)-1:])
        for i in range(min(len(extension), len(packet[-1]))):
            if packet[-1][i] != "":
                if extension[i] not in self.extension:
                    self.extension.setdefault(extension[i],[])
                self.extension[extension[i]].append((packet[-1][i],len(self.ip_lengths)))


        # Set timestamps and lengths
        #print(packet)
        self.ip_timestamps.append(float(packet[3]))
        self.ip_lengths   .append( int(packet[4]) if (packet[5], int(packet[7])) == (self.src, self.sport) else
                               -int(packet[4]))
        if int(packet[9]) != 0:
            try:
                self.payload_lengths.append( int(packet[9]) if (packet[5], int(packet[7])) == (self.src, self.sport) else
                                   -int(packet[9]))
                self.payload_timestamps.append(float(packet[3]))
            except BaseException as exp:
                raise ValueError('Parser payload length and timestamp error, this ip packet may not be a sample of tcp or udp. Please pass the filter parameter with `(tcp or udp)` when invoke flowcontainer.extractor.extract()!')

        # Return self
        return self

    ########################################################################
    #                  Source/Destination/Time attributes                  #
    ########################################################################

    @property
    def source(self):
        """(source IP, source port)-tuple of Flow"""
        return (self.src, self.sport)

    @property
    def destination(self):
        """(destination IP, destination port)-tuple of Flow"""
        return (self.dst, self.dport)

    @property
    def time_start(self):
        """Returns start time of Flow"""
        return min(self.timestamps)
    @property
    def ext_protocol(self):
        return "|".join(self._ext_protocols)
    @property
    def time_end(self):
        """Returns end time of Flow"""
        return max(self.timestamps)

    ########################################################################
    #                           Class overrides                            #
    ########################################################################

    def __len__(self):
        """Return length of Flow in packets."""
        return len(self.lengths)

    def __str__(self):
        """Return string representation of flow."""
        if self.main=='ip':
            return "[Time {} to {}] {:>15}:{:<5} <-> {:>15}:{:<5} [IP Packet Size Length {}] [extension: {}]".format(
                datetime.fromtimestamp(min(self.timestamps)).strftime("%H:%M:%S.%f"),
                datetime.fromtimestamp(max(self.timestamps)).strftime("%H:%M:%S.%f"),
                self.src, self.sport, self.dst, self.dport,
                len(self),self.extension)
        else:
            return "[Time {} to {}] {:>15}:{:<5} <-> {:>15}:{:<5} [Payload Packet Size Length {}] [extension: {}]".format(
                datetime.fromtimestamp(min(self.timestamps)).strftime("%H:%M:%S.%f"),
                datetime.fromtimestamp(max(self.timestamps)).strftime("%H:%M:%S.%f"),
                self.src, self.sport, self.dst, self.dport,
                len(self),self.extension)
    def __gt__(self, other):
        """Greater than object override"""
        return min(self.timestamps) >  min(other.timestamps)

    def __ge__(self, other):
        """Greater equals object override"""
        return min(self.timestamps) >= min(other.timestamps)

    def __lt__(self, other):
        """Less than object override"""
        return min(self.timestamps) <  min(other.timestamps)

    def __le__(self, other):
        """Less equals object override"""
        return min(self.timestamps) <= min(other.timestamps)