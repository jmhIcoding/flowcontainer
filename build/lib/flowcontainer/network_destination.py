from collections import Counter

class NetworkDestination(object):
    """NetworkDestination object for flow samples

        Attributes
        ----------
        identifier : object
            Unique identifier for NetworkDestination

        samples : list
            List of flows stored in NetworkDestination

        destinations : set
            Set of destination (IP, port) tuples related to NetworkDestination

        certificates : set
            Set of TLS certificates related to NetworkDestination

        labels : Counter
            Labels related to NetworkDestination
    """

    def __init__(self, identifier, samples=[]):
        """NetworkDestination object for flow samples

            Parameters
            ----------
            identifier : object
                Identifier for NetworkDestination
                Important: identifier must be unique!

            samples : iterable of Flow
                Samples to store in this NetworkDestination.
            """
        # Initialise variables
        self.identifier   = identifier
        self.samples      = []
        self.destinations = set()
        self.certificates = set()
        self.labels       = Counter()

        # Add each datapoint
        for X in samples:
            self.add(X)

    ########################################################################
    #                         Add flows to cluster                         #
    ########################################################################

    def add(self, X, y=None):
        """Add flow X to NetworkDestination object.

            Parameters
            ----------
            X : Flow
                Datapoint to store in this NetworkDestination.

            y : object
                Label for datapoint
            """
        # Add datapoint
        self.samples.append(X)
        self.labels.update([y])
        # Update pointers
        self.destinations.add(X.destination)
        self.certificates.add(X.certificate)


    def merge(self, other):
        """Merge NetworkDestination with other NetworkDestination object.

            Parameters
            ----------
            other : NetworkDestination
                Other NetworkDestination object to merge with.
            """
        # Only merge in case other is NetworkDestination object
        if isinstance(other, NetworkDestination):
            # Merge two NetworkDestinations
            self.samples.extend(other.samples)
            # Merge pointers
            self.destinations |= other.destinations
            self.certificates |= other.certificates
            self.labels += other.labels

    ########################################################################
    #                           Get description                            #
    ########################################################################

    def get_description(self):
        """Returns human readable description of cluster"""
        # Get descriptions
        descr_cert = [X.certificate for X in self.samples]
        descr_ip   = ["{}".format(X.destination) for X in self.samples]
        # Remove None values
        descr_cert = [x for x in descr_cert if x is not None]
        descr_ip   = [x for x in descr_ip   if x is not None]
        # Get most common
        descr_cert = Counter(descr_cert).most_common(1)
        descr_ip   = Counter(descr_ip  ).most_common(1)
        # Return description
        try   : return descr_cert[0][0]
        except: return descr_ip[0][0]

    ########################################################################
    #                           Object overrides                           #
    ########################################################################

    def __str__(self):
        """Returns string presentation of self."""
        return "NetworkDestination [{:4}] [size={:4}] [IPs={}] [labels={}]".\
                format(self.identifier, len(self.samples),
                list(sorted(self.destinations)), self.labels)
