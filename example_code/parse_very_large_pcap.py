__author__ = 'dk'
__author__ = 'dk'
#coding:utf8
import time
from flowcontainer.extractor import extract
stime = time.time()

## tid_ssl是一个600MB的PCAP文件.
## 当split_flag设置为True，开启PCAP切分功能，那么处理时长为127秒。
## 当split_flag设置为False时，处理时长为160秒。
## 通过把大的PCAP切分为小的PCAP文件可以带来明显的性能提升

result = extract(r"E:\tempworkstation\msclouds\traffic_parser\tid_ssl.pcap",
                 filter='ip',
                 extension=[],
                 split_flag=True,
                 verbose=True
            )
etime = time.time()

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

    print('start timestamp:{0}, end timestamp :{1}'.format(value.time_start,value.time_end))
    ##access sni of the flow if any else empty str
    print('extension:',value.extension)

print(etime-stime)
print(len(result))