# 库介绍
flowcontainer是基于python3的网络流量基本信息提取库，以方便完成网络流量的分析任务。给定pcap文件，该库会提取pcap所有的流的相关信息，其中流信息包括：流的源端口、源IP、目的IP、目的端口、IP数据包的长度序列、IP数据集的到达时间序列、有效载荷序列以及相应有效载荷的到达时间序列、等扩展信息。库会对IP数据包做过滤，那些tcp/udp载荷不为0的数据包会统计到有效载荷序列里面。工具简单易用，扩展性和复用性高。
# 博客地址
[flowcontainer: 基于python3的网络流量特征信息提取库](https://blog.csdn.net/jmh1996/article/details/107148871)

url: https://blog.csdn.net/jmh1996/article/details/107148871

【github有时解析markdown里面的公式出错，因此请移步博客，获取更好的文档阅读体验】
# 库的安装
最新版：
```bash
pip3 install git+https://github.com/jmhIcoding/flowcontainer.git
```
稳定版：
```bash
pip3 install flowcontainer
```
# 库的环境

- python 3
- numpy>=18.1
- 系统安装好wireshark的最新版本（3.0.0）,并将tshark所在的目录添加到系统的环境目录。安装好wireshark就会顺带把tshark也安装好。

**如果只是提取流的端口号、包长序列等基本信息，tshark的版本号只需大于2.6.0即可。**

**如果需要提取tls的sni,那么tshark的版本需要大于3.0.0。**

**如果需要提取upd.payload,那么tshark的版本需要大于3.3.0**

<font color="red" >
<bold>另外，请确保运行脚本的shell（尤其是pycharm和vscode里面的shell）能够正确运行 tshark ! 否则程序一定报错！</bold> </font>

# 解析速度
50G左右的流量2个小时左右即可完成所有流信息的提取。5G左右的流量12分钟即可解析完毕。
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
# 库的使用
示例代码：
直接导入extract函数，然后给定pcap的路径即可。



- 打开pcap文件，同时设置过滤规则和扩展规则。

**flowcontainer默认滤除重传、乱序数据包、mdns、ssdp、icmp数据包，默认只保留IP数据包。
flowcontainer默认提取流的：源IP，源端口，目的IP，目的端口，IP包长序列，IP包到达时间序列，流到达时间戳、流结束时间戳、载荷长度序列，载荷到达时间序列。**


`extract`函数接受3个参数：`infile,filter,extension`。

其中:
`infile` 用于标识pcap文件路径。
`filter` 用于添加包过滤规则，过滤规则的语义和语法规则与wireshark严格保持一致。可以为空。
`extension` 是用于需要提取的额外的扩展字段，字段语义和语法规则也与wireshark严格保持一致。可以为空。

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
# 示例输出：
代码：
```python
__author__ = 'dk'
from flowcontainer.extractor import extract
result = extract(r"1592993485_clear.pcap",filter='',extension=['tls.handshake.ciphersuite'])

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

print(len(result))
```

上面这段代码会提取流的基本信息，同时提取ssl流的sni，示例输出：
```python
Reading 1592993485_clear.pcap...
Flow ('1592993485_clear.pcap', 'tcp', '0') info:
src ip: 192.168.0.100
dst ip: 208.43.237.140
sport: 44524
dport: 443
payload lengths : [180, -1388, -1448, -216, 126, -274, 625, -1163, 361, -1092, 361, -1092, 361, -1092, 351, -888, 672, 34, -672, 935, 34, -672, 877, 34, -672]
payload timestamps: [1592993502.710375, 1592993502.718662, 1592993502.718675, 1592993502.993874, 1592993502.993886, 1592993502.993898, 1592993502.993909, 1592993503.234205, 1592993504.233183, 1592993504.233191, 1592993510.790214, 1592993510.790245, 1592993511.56349, 1592993511.563504, 1592993511.908443, 1592993511.90846, 1592993513.319068, 1592993513.31908, 1592993513.319091, 1592993517.633375, 1592993517.769362, 1592993518.085971, 1592993532.423575, 1592993532.576553, 1592993532.725287]
ip packets lengths: [60, -60, 52, 232, -52, -1440, 52, -1500, 52, -268, 52, 178, -52, -326, 52, 677, -52, -1215, 52, 413, -52, -1144, 52, 413, -52, -1144, 52, 413, -52, -1144, 52, 403, -52, -940, 52, 724, -52, 86, -52, -724, 52, 987, -52, 86, -52, -724, 52, 929, -52, 86, -52, -724, 52, -52, 52, 52, -52]
ip packets timestamps: [1592993502.710348, 1592993502.710361, 1592993502.710369, 1592993502.710375, 1592993502.71038, 1592993502.718662, 1592993502.718672, 1592993502.718675, 1592993502.718798, 1592993502.993874, 1592993502.993883, 1592993502.993886, 1592993502.993889, 1592993502.993898, 1592993502.993901, 1592993502.993909, 1592993502.994026, 1592993503.234205, 1592993503.234209, 1592993504.233183, 1592993504.233187, 1592993504.233191, 1592993504.233196, 1592993510.790214, 1592993510.790238, 1592993510.790245, 1592993510.790252, 1592993511.56349, 1592993511.563498, 1592993511.563504, 1592993511.563511, 1592993511.908443, 1592993511.908448, 1592993511.90846, 1592993512.333793, 1592993513.319068, 1592993513.319074, 1592993513.31908, 1592993513.319085, 1592993513.319091, 1592993513.319097, 1592993517.633375, 1592993517.769339, 1592993517.769362, 1592993517.769368, 1592993518.085971, 1592993518.086312, 1592993532.423575, 1592993532.576529, 1592993532.576553, 1592993532.576559, 1592993532.725287, 1592993532.725293, 1592993547.830937, 1592993547.83094, 1592993552.653862, 1592993552.899427]
default length sequence: [180, -1388, -1448, -216, 126, -274, 625, -1163, 361, -1092, 361, -1092, 361, -1092, 351, -888, 672, 34, -672, 935, 34, -672, 877, 34, -672]
default timestamp sequence: [1592993502.710375, 1592993502.718662, 1592993502.718675, 1592993502.993874, 1592993502.993886, 1592993502.993898, 1592993502.993909, 1592993503.234205, 1592993504.233183, 1592993504.233191, 1592993510.790214, 1592993510.790245, 1592993511.56349, 1592993511.563504, 1592993511.908443, 1592993511.90846, 1592993513.319068, 1592993513.31908, 1592993513.319091, 1592993517.633375, 1592993517.769362, 1592993518.085971, 1592993532.423575, 1592993532.576553, 1592993532.725287]
start timestamp:1592993502.710375, end timestamp :1592993532.725287
extension: {'tls.handshake.ciphersuite': [('49195,49196,52393,49199,49200,52392,49161,49162,49171,49172,156,157,47,53', 3), ('49195', 5)]}
Flow ('1592993485_clear.pcap', 'tcp', '1') info:
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

# 安装人数统计
从pypi可以查询到每个月通过pip安装flowcontainer的人数信息：
|下载数| 月份 |
|--|--|
|  1944|2020-11  |
|1315|2020-10|
|1196|2020-09|


