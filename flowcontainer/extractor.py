__author__ = 'dk'
from flowcontainer.reader import Reader
from flowcontainer.flow_generator import FlowGenerator
def extract(infile,filter="(tcp or udp or gre)",extension="", ip_layer=False):
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

    reader = Reader(verbose=True)
    flow_generator = FlowGenerator()
    # Read packets
    result = reader.read(infile,filter,extension,ip_layer)
    # Combine packets into flows
    result = flow_generator.combine(result,extension)
    # Return result
    return result