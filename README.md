# 库介绍
flowcontainer是由信息工程研究所智能信息对抗组开源的基于python3的网络流量基本信息提取库，以方便完成网络流量的分析任务。给定pcap文件，该库会提取pcap所有的流的相关信息，其中流信息包括：流的源端口、源IP、目的IP、目的端口、IP数据包的长度序列、IP数据包的到达时间序列、有效载荷序列以及相应有效载荷的到达时间序列、协议类型等扩展信息。库会对IP（IPv6) 数据包做过滤，那些tcp/udp载荷不为0的数据包会统计到有效载荷序列里面。工具简单易用，扩展性和复用性高。
# 博客地址
[flowcontainer: 基于python3的网络流量特征信息提取库](https://blog.csdn.net/jmh1996/article/details/107148871)
【github有时解析markdown里面的公式出错，因此请移步博客，获取更好的文档阅读体验】
# 库的安装

```bash
pip3 install flowcontainer
```
# 库的环境

- python 3
- numpy>=18.1
- 系统安装好wireshark的最新版本（3.0.0）,并将tshark所在的目录添加到系统的环境目录。安装好wireshark就会顺带把tshark也安装好。
<font color="red" >
<bold> Wireshark 4.x 相比Wireshark 3.x做了重大变化，因此不要安装 4.x的wireshark,否则可能出错!
</bold> </font>

- splitpcap, 大型PCAP切分工具。 该工具能够将大型PCAP文件切分为一系列较小的PCAP文件，加快解析速度。安装指南： https://github.com/jmhIcoding/splitpcap。

**如果只是提取流的端口号、包长序列等基本信息，tshark的版本号只需大于2.6.0即可。**

**如果需要提取tls的sni,那么tshark的版本需要大于3.0.0。**

**如果需要提取upd.payload,那么tshark的版本需要大于3.3.0**

<font color="red" >
<bold>另外，请确保运行脚本的shell（尤其是pycharm和vscode里面的shell）能够正确运行 tshark 和splitpcap ! 否则程序一定报错！</bold> </font>

# 解析速度
50G左右的流量2个小时左右即可完成所有流信息的提取。5G左右的流量12分钟即可解析完毕。


# 库的使用
示例代码：
直接导入extract函数，然后给定pcap的路径即可。



- 打开pcap文件，同时设置过滤规则和扩展规则。

**flowcontainer默认滤除重传、乱序数据包、mdns、ssdp、icmp数据包，默认只保留IP数据包。
flowcontainer默认提取流的：源IP，源端口，目的IP，目的端口，IP包长序列，IP包到达时间序列，流到达时间戳、流结束时间戳、载荷长度序列，载荷到达时间序列。**

**最新版本flowcontainer，支持ipv6解析。**


`extract`函数接受4个参数：`infile,filter,extension,split_flag`。

其中:
`infile` 用于标识pcap文件路径。
`filter` 用于添加包过滤规则，过滤规则的语义和语法规则与wireshark严格保持一致。可以为空。
`extension` 是用于需要提取的额外的扩展字段，字段语义和语法规则也与wireshark严格保持一致。可以为空。
`split_flag` 默认为`False`，如果被设置为`True`，那么将会对输入的PCAP按照流的五元组切分得到$M$个小PCAP文件，接着再使用线程池并发地解析$M$个小PCAP文件。当输入的PCAP比较大时，开启`split_flag`通常能得到解析速度的提升。

**flowcontainer 兼容wireshark所有特殊扩展字段提取，例如X509证书、SNI、SSL的ciphersuites、tcp载荷、udp载荷、ipid字段等等。**

```python
__author__ = 'dk'
from flowcontainer.extractor import extract
result = extract(r"1592754322_clear.pcap",filter='',extension=["tls.handshake.extensions_server_name","tls.handshake.ciphersuite"])
```
- 获取pcap里面流的信息

extract的返回值是一个字典。
每条流由key索引，key 是一个元组：`（pcap文件名，传输层协议，流的ID号）`。例如：`('1592754322_clear.pcap', 'tcp', '1')`

- 使用for循环来遍历流：
```python
for key in result:
    ### The return vlaue result is a dict, the key is a tuple (filename,procotol,stream_id)
    ### and the value is an Flow object, user can access Flow object as flowcontainer.flows.Flow's attributes refer.

    value = result[key]
    print('Flow {0} info:'.format(key))
 ```
- **提取流的源IP**
 ```python
    ## access ip src
    print('src ip:',value.src)
 ```
- **提取流的目的IP**
 ```python
    ## access ip dst
    print('dst ip:',value.dst)
 ```
- **提取流的端口信息**
```python
    ## access srcport
    print('sport:',value.sport)
    ## access_dstport
    print('dport:',value.dport)
```

- **访问载荷长度序列和到达时间序列**
```python
    ## access payload packet lengths
    print('payload lengths :',value.payload_lengths)
    ## access payload packet timestamps sequence:
    print('payload timestamps:',value.payload_timestamps)
```
包长序列是带正负号的，正负号用于标识数据包是客户端发往服务端还是由服务端发往客户端。正数标识C->S的数据包，负数标识S->C 的数据包。

- **访问流的开始时间和结束时间**

```python
	print('start timestamp :',value.time_start)
	print('end timestamp :',value.time_end)
```
需要注意的是，这里流的开始时间和结束时间是基于默认的时间戳 **【目前是有效载荷序列的时间戳，而不是IP数据包的时间戳】** 来计算的。其中`time_start` 通过`min(value.timestamps)` 得到，而`time_end` 通过 `max(value.timestamps)`得到。

- **访问IP包长度序列和到达时间序列**

这个序列和载荷序列的区别在于：载荷序列是tcp/udp载荷不为空的tcp/udp载荷序列。IP包序列会把那些握手包，无载荷的tcp/udp包也统计进来。

```python
    ## access ip packet lengths, (including packets with zero payload, and ip header)
    print('ip packets lengths:',value.ip_lengths)
    ## access ip packet timestamp sequence, (including packets with zero payload)
    print('ip packets timestamps:',value.ip_timestamps)
```
包长序列是带正负号的，正负号用于标识数据包是客户端发往服务端还是由服务端发往客户端。正数标识C->S的数据包，负数标识S->C 的数据包。

- **访问默认序列信息，默认是载荷序列信息**
```python
    ## access default lengths sequence, the default length sequences is the payload lengths sequences
    print('default length sequence:',value.lengths)
    ## access default timestamp sequence, the default timestamp sequence is the payload timestamp sequences
    print('default timestamp sequence:',value.timestamps)
```
包长序列是带正负号的，正负号用于标识数据包是客户端发往服务端还是由服务端发往客户端。正数标识C->S的数据包，负数标识S->C 的数据包。

- **访问扩展协议类型**
这个数据主要对应的是wireshark里面显示的协议那一栏，例如DNS/TLSv1.2/TLSv1.1 等等。
```python
	print("proto:", value.ext_protocol)
```

- **访问扩展字段**
```python
    ##access sni of the flow if any else empty str
    print('extension:',value.extension)
```
值得注意的是，extension是一个dict，里面的key就是用户自己指定的extension里面的各个item。而每个key对应的value是一个list,表示在整条里面用户需要的extension所出现过的取值以及该扩展取值在这条流的IP数据包出现的下标。

我们以提取TLS握手阶段的ciphersuites为例，我们给extensions参数传入实参：`tls.handshake.ciphersuite` ，那么出来的结果类似于：
```python
src ip: 192.168.0.100
dst ip: 208.43.237.140
sport: 44525
dport: 443
payload lengths : [180, -1424, -1440, -190, 126, -274, 625, -1163, 31, -31]
payload timestamps: [1592993502.710372, 1592993502.710383, 1592993502.71261, 1592993502.712895, 1592993502.993892, 1592993502.993903, 1592993503.234192, 1592993504.233002, 1592993527.490709, 1592993527.49081]
ip packets lengths: [60, -60, 52, 232, -52, -1476, 52, -1492, 52, -242, 52, 178, -52, -326, 52, 677, -52, -1215, 52, -52, 52, 83, -52, 52, -83, 40, -52, 40]
ip packets timestamps: [1592993502.710358, 1592993502.710364, 1592993502.710366, 1592993502.710372, 1592993502.710377, 1592993502.710383, 1592993502.710386, 1592993502.71261, 1592993502.712891, 1592993502.712895, 1592993502.712898, 1592993502.993892, 1592993502.993895, 1592993502.993903, 1592993502.993906, 1592993503.234192, 1592993503.234202, 1592993504.233002, 1592993504.233179, 1592993518.51743, 1592993518.517824, 1592993527.490709, 1592993527.490712, 1592993527.490716, 1592993527.49081, 1592993527.490818, 1592993527.490821, 1592993527.490824]
default length sequence: [180, -1424, -1440, -190, 126, -274, 625, -1163, 31, -31]
default timestamp sequence: [1592993502.710372, 1592993502.710383, 1592993502.71261, 1592993502.712895, 1592993502.993892, 1592993502.993903, 1592993503.234192, 1592993504.233002, 1592993527.490709, 1592993527.49081]
start timestamp:1592993502.710372, end timestamp :1592993527.49081
extension: {'tls.handshake.ciphersuite': [('49195,49196,52393,49199,49200,52392,49161,49162,49171,49172,156,157,47,53', 3), ('49195', 5)]}

```
extension是一个字典，key就是传入的`tls.handshake.ciphersuite`，而value是一个list，list的每个元素是个tuple，其中tuple[0] 是具体的取值，tuple[1]表示该取值在这条流第几个IP数据包出现。tuple[1]这个位置信息是有意义的，

因为SSL握手阶段的ciphersuites，既有client 到server提供的ciphersuites，也有服务器最终选择的ciphersuites。需要通过联合判断ciphersuites所在packet的方向（outgoing 还是incoming） 才能知道ciphersuites到底是那一侧的取值。

在这个实例里面，list有两个元素。第一个是`('49195,49196,52393,49199,49200,52392,49161,49162,49171,49172,156,157,47,53', 3)`，表示
在这条流里面，第3个IP数据包出现了ciphersuites,然后ciphersuites的取值是`'49195,49196,52393,49199,49200,52392,49161,49162,49171,49172,156,157,47,53'`，通过查看ip长度序列可知第三个长度是232（下标从0计数），这是一个由客户端发送给服务端的outgoing数据包，因此这是c2s的加密套件。
第二个取值`('49195', 5)` ,表示这条流的第5个IP数据包出现了ciphersuits，而且取值为49195，查IP长度序列可知它对应长度是 -1476，这是一个由服务器响应而来的数据包，因此这个ciphersuits就是服务器选择的加密套件。

常见扩展字段：

| 字段名 | extension取值 |备注|
|--|--|--|
| sni | tls.handshake.extensions_server_name |tshark版本 $\ge$ 3.0.0|
|ssl的cipher_suits|tls.handshake.ciphersuite|tshark版本 $\ge$ 3.0.0|
|x509证书|tls.handshake.certificate|tshark版本 $\ge$ 3.0.0|
|udp载荷|udp.payload|tshark版本 $\ge$ **3.3.0**|
|tcp载荷|tcp.payload|无|

此外，tshark不允许对同一个字段，连续提取多次。**因此切勿在extensions里面对udp/tcp的长度、ip长度、ip地址、端口号等默认提取的字段做二次提取，否则会出现编码解析的错误！**

# 样例
## 简单例程
下面的代码展示了flowcontainer 最基本的用法：
```python
__author__ = 'dk'
__author__ = 'dk'
#coding:utf8
import time
from flowcontainer.extractor import extract
stime = time.time()

result = extract(r"1592993485_noise.pcap",
                 filter='ip',
                 extension=[],
                 split_flag=False,
                 verbose=True
            )
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

    ## access the proto
    print('proto:', value.ext_protocol)
    ##access sni of the flow if any else empty str
    print('extension:',value.extension)

```

上面这段代码会提取流的基本信息，同时提取ssl流的加密套件，示例输出：
```python
Flow ('1592993485_noise.pcap', 'udp', '150') info:
src ip: 192.168.0.100
dst ip: 223.111.239.177
sport: 44738
dport: 1516
payload lengths : [44, 44, 44, 44, 44, 44, 44, 44, 44, 44]
payload timestamps: [1592993550.021676, 1592993550.136188, 1592993550.258189, 1592993550.543668, 1592993550.646864, 1592993550.76075, 1592993550.866083, 1592993550.969658, 1592993551.071932, 1592993551.179754]
ip packets lengths: [64, 64, 64, 64, 64, 64, 64, 64, 64, 64]
ip packets timestamps: [1592993550.021676, 1592993550.136188, 1592993550.258189, 1592993550.543668, 1592993550.646864, 1592993550.76075, 1592993550.866083, 1592993550.969658, 1592993551.071932, 1592993551.179754]
default length sequence: [44, 44, 44, 44, 44, 44, 44, 44, 44, 44]
default timestamp sequence: [1592993550.021676, 1592993550.136188, 1592993550.258189, 1592993550.543668, 1592993550.646864, 1592993550.76075, 1592993550.866083, 1592993550.969658, 1592993551.071932, 1592993551.179754]
start timestamp:1592993550.021676, end timestamp :1592993551.179754
proto: UDP
extension: {}
Flow ('1592993485_noise.pcap', 'tcp', '94') info:
src ip: 192.168.0.100
dst ip: 164.90.117.68
sport: 42930
dport: 443
payload lengths : [213, -1448, -600, -816, -1448, -600, -832, -289, 126, -343]
payload timestamps: [1592993550.690015, 1592993551.035379, 1592993551.035632, 1592993551.035762, 1592993551.037588, 1592993551.037816, 1592993551.037952, 1592993551.03886, 1592993551.044419, 1592993551.08717]
ip packets lengths: [60, -60, 52, 265, -52, -1500, 52, -652, 52, -868, 52, -1500, 52, -652, 52, -884, 52, -341, 52, 178, -52, -395, 52, 52]
ip packets timestamps: [1592993550.677152, 1592993550.688842, 1592993550.689094, 1592993550.690015, 1592993550.69185, 1592993551.035379, 1592993551.035582, 1592993551.035632, 1592993551.035708, 1592993551.035762, 1592993551.035871, 1592993551.037588, 1592993551.037759, 1592993551.037816, 1592993551.037916, 1592993551.037952, 1592993551.038041, 1592993551.03886, 1592993551.039023, 1592993551.044419, 1592993551.046253, 1592993551.08717, 1592993551.12293, 1592993552.929707]
default length sequence: [213, -1448, -600, -816, -1448, -600, -832, -289, 126, -343]
default timestamp sequence: [1592993550.690015, 1592993551.035379, 1592993551.035632, 1592993551.035762, 1592993551.037588, 1592993551.037816, 1592993551.037952, 1592993551.03886, 1592993551.044419, 1592993551.08717]
start timestamp:1592993550.690015, end timestamp :1592993551.08717
proto: TLSv1.2|TCP
extension: {}
```

## 其他例程
在example_code文件夹里面，有多个使用flowcontainer获取流量信息的案例。

- easy_example.py 
展示了如何获取网络流量的包长、包到达间隔等信息，这些信息对于开展加密网络流分析实验特别重要
- parse_very_large_pcap.py 
展示了如何使用流量切分加速解析超大PCAP文件。
- http 
HTTP流量解析案例，案例展示了如何获取HTTP的User-agent, http-url等。

示例输出：
```
{'pcapname': 'nat.pcap', 'src_ip': '172.16.30.159', 'sport': 46648, 'dst_ip': '61.149.22.99', 'dport': 80, 'protocol': 'tcp', 'ext_proto': 'HTTP', 'start': 1521603003.580238, 'end': 1521603003.580238, 'http.user_agent': 'NeteaseMusic/5.0.0.1520384820(115);Dalvik/2.1.0 (Linux; U; Android 8.0.0; STF-AL00 Build/HUAWEISTF-AL00)', 'http.request.full_uri': 'http://p2.music.126.net/SbJn22gsq-Pv6WLm8PK98A==/564049465093755.jpg?imageView=1&thumbnail=360z360&type=webp&quality=80', 'http.host': 'p2.music.126.net'}
```
- dns 
 DNS流量解析案例，案例展示了如何解析DNS的A记录等。
```
{'pcapname': 'dns.pcapng', 'src_ip': '192.168.172.51', 'sport': 51518, 'dst_ip': '8.8.8.8', 'dport': 53, 'protocol': 'udp', 'ext_proto': 'DNS', 'start': 1669704818, 'end': 1669704818, 'dns_records': [{'NAME': 'dns.google', 'TYPE': 'A', 'ADDRESS': '8.8.8.8'}, {'NAME': 'dns.google', 'TYPE': 'A', 'ADDRESS': '8.8.4.4'}]}
```
- ssl 
SSL流量解析案例，案例展示了如何获取SNI、证书，以及如何解析流量中的X509证书。
```
{'pcapname': 'tid_ssl.pcap', 'src_ip': '119.78.131.162', 'sport': 50665, 'dst_ip': '23.56.20.10', 'dport': 443, 'protocol': 'tcp', 'ext_proto': 'TLSv1.2', 'start': 1597319999.645109, 'end': 1597319999.732076, 'sni': 'c.go-mpulse.net', 'cipher_suites': '49192,49191,49172,49171,159,158,57,51,157,156,61,60,53,47,49196,49195,49188,49187,49162,49161,106,64,56,50,10,19|49196', 'certificates': [{'issuer': {'countryName': 'US', 'organizationName': 'DigiCert Inc', 'organizationalUnitName': 'www.digicert.com', 'commonName': 'DigiCert Secure Site ECC CA-1'}, 'subject': {'countryName': 'US', 'stateOrProvinceName': 'Massachusetts', 'localityName': 'Cambridge', 'organizationName': 'Akamai Technologies', 'organizationalUnitName': 'SOASTA', 'commonName': 'akstat.io'}, 'not_valid_before': '2020-05-06 00:00:00', 'not_valid_after': '2021-08-05 12:00:00', 'seriral_number': 12148336732659377462193089635366108055, 'version': 'v3'}, {'issuer': {'countryName': 'US', 'organizationName': 'DigiCert Inc', 'organizationalUnitName': 'www.digicert.com', 'commonName': 'DigiCert Global Root CA'}, 'subject': {'countryName': 'US', 'organizationName': 'DigiCert Inc', 'organizationalUnitName': 'www.digicert.com', 'commonName': 'DigiCert Secure Site ECC CA-1'}, 'not_valid_before': '2019-02-15 12:45:24', 'not_valid_after': '2029-02-15 12:45:24', 'seriral_number': 15099003683604006848814258862226398944, 'version': 'v3'}]}
```

# 常见问题以及排除
- 报找不到文件的错误。
解决方法：1. 检查pcap的路径是否正确，最好使用绝对路径  2. 检查当前shell能否打开tshark ，确保环境变量有tshark所在路径。3. 检查tshark版本，是否在2.6.0以上。

此ISSUE 致谢：宝哥
- 报 ValueError: invalid literal for int() with base 10: 错误
异常输出：
```shell
if int(packet[9]) != 0:
ValueError: invalid literal for int() with base 10: ''
```
解决方法：1. 在extract函数调用时，指定filter为`tcp or udp` 。这是因为pcap里面出现了非tcp/udp的packet，导致端口信息无法正常定位。**2. tshark不允许对同一个字段，连续提取多次。因此切勿在extensions里面对udp/tcp的长度、ip长度、ip地址、端口号做二次提取。**

此ISSUE 致谢：宝哥

- 其他问题： 请在github提交issue,然后上传出问题的数据包和调用例程方便解决问题。

