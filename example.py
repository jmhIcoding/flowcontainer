__author__ = 'dk'
from flowcontainer.extractor import extract
result = extract(r"1592754322_clear.pcap",filter='(tcp or udp)',extension=['tls.handshake.certificate'])

for key in result:
    ### The return vlaue result is a dict, the key is a tuple (filename,procotol,stream_id)
    ### and the value is an Flow object, user can access Flow object as flowcontainer.flows.Flow's attributes refer.

    value = result[key]
    print('Flow {0} info:'.format(key))
    ## access ip src
    print('src ip:',value.src)
    ## access ip dst
    print('dst ip:',value.dst)
    ## access srcport
    print('sport:',value.sport)
    ## access_dstport
    print('dport:',value.dport)
    ## access payload packet lengths
    print('payload lengths :',value.payload_lengths)
    ## access payload packet timestamps sequence:
    print('payload timestamps:',value.payload_timestamps)
    ## access ip packet lengths, (including packets with zero payload, and ip header)
    print('ip packets lengths:',value.ip_lengths)
    ## access ip packet timestamp sequence, (including packets with zero payload)
    print('ip packets timestamps:',value.ip_timestamps)

    ## access default lengths sequence, the default length sequences is the payload lengths sequences
    print('default length sequence:',value.lengths)
    ## access default timestamp sequence, the default timestamp sequence is the payload timestamp sequences
    print('default timestamp sequence:',value.timestamps)

    ##access sni of the flow if any else empty str
    print('extension:',value.extension)

print(len(result))