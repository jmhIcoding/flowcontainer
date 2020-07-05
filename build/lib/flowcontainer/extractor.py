__author__ = 'dk'
from flowcontainer.reader import Reader
from flowcontainer.flow_generator import FlowGenerator
def extract(infile):
    """Extract flows from given pcap file.

        Parameters
        ----------
        infile : string
            Path to input file.

        Returns
        -------
        result : dict
            Dictionary of flow_key -> flow.
        """
    reader = Reader(verbose=True)
    flow_generator = FlowGenerator()
    # Read packets
    result = reader.read(infile)
    # Combine packets into flows
    result = flow_generator.combine(result)
    # Return result
    return result