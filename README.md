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



- 打开pcap文件，同时设置过滤规则和过滤规则。

**flowcontainer默认滤除重传、乱序数据包、mdns、ssdp、icmp数据包，默认只保留IP数据包。
flowcontainer默认提取流的：源IP，源端口，目的IP，目的端口，IP包长序列，IP包到达时间序列，载荷长度序列，载荷到达时间序列。**

`extract`函数接受3个参数：`infile,filter,extension`。

其中:
`infile` 用于标识pcap文件路径。
`filter` 用于添加包过滤规则，过滤规则的语义和语法规则与wireshark严格保持一致。可以为空。
`extension` 是用于需要提取的额外的扩展字段，字段语义和语法规则也与wireshark严格保持一致。可以为空。


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
- **访问流的开始时间和结束时间**

```python
	print('start timestamp :',value.time_start)
	print('end timestamp :',value.time_end)
```
需要注意的是，这里流的开始时间和结束时间是基于默认的时间戳【目前是有效载荷序列的时间戳，而不是IP数据包的时间戳】来计算的。

- **访问IP包长度序列和到达时间序列**

这个序列和载荷序列的区别在于：载荷序列是tcp/udp载荷不为空的tcp/udp载荷序列。IP包序列会把那些握手包，无载荷的tcp/udp包也统计进来。

```python
    ## access ip packet lengths, (including packets with zero payload, and ip header)
    print('ip packets lengths:',value.ip_lengths)
    ## access ip packet timestamp sequence, (including packets with zero payload)
    print('ip packets timestamps:',value.ip_timestamps)
```
- **访问默认序列信息，默认是载荷序列信息**
```python
    ## access default lengths sequence, the default length sequences is the payload lengths sequences
    print('default length sequence:',value.lengths)
    ## access default timestamp sequence, the default timestamp sequence is the payload timestamp sequences
    print('default timestamp sequence:',value.timestamps)
```

- **访问扩展字段**
```python
    ##access sni of the flow if any else empty str
    print('extension:',value.extension)
```
值得注意的是，extension是一个dict，里面的key就是用户自己指定的extension里面的各个item。而每个key对应的value是一个list,表示在整条里面用户需要的extension所出现过的取值。**list的长度与ip包长序列【并不是载荷长度序列】的长度是一样的，表示对于每个ip packet都会提取extension所需的字段，如果当前ip packet没有这个字段，那么该字段的取值为空字符串`''`，否则为实际的取值。之所以保留空字符串，是方便IP长度与扩展之间的对齐，实际使用中如果不需要此类对齐信息，请注意过滤list里面的空字符串。**

此外，tshark不允许对同一个字段，连续提取多次。**因此切勿在extensions里面对udp/tcp的长度、ip长度、ip地址、端口号做二次提取**。

常见扩展字段：

| 字段名 | extension取值 |备注|
|--|--|--|
| sni | tls.handshake.extensions_server_name |tshark版本 $\ge$ 3.0.0|
|ssl的cipher_suits|tls.handshake.ciphersuite|tshark版本 $\ge$ 3.0.0|
|x509证书|tls.handshake.certificate|tshark版本 $\ge$ 3.0.0|
|udp载荷|udp.payload|tshark版本 $\ge$ **3.3.0**|
|tcp载荷|tcp.payload|无|


# 示例输出：
代码：
```python
__author__ = 'dk'
from flowcontainer.extractor import extract
result = extract(r"1592754322_clear.pcap",filter='(tcp or udp)',extension=['tls.handshake.extensions_server_name'])

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
```

上面这段代码会提取流的基本信息，同时提取ssl流的sni，示例输出：
```python
Flow ('1592754322_clear.pcap', 'tcp', '2') info:
src ip: 10.82.8.58
dst ip: 87.240.137.206
sport: 48943
dport: 443
payload lengths : [171, -1370, -1024]
payload timestamps: [1592754332.516003, 1592754333.506533, 1592754341.157636]
ip packets lengths: [60, -52, 40, 211, -1410, 40, -1064, 40, 40, -40, 40]
ip packets timestamps: [1592754329.508596, 1592754332.515984, 1592754332.515993, 1592754332.516003, 1592754333.506533, 1592754333.506548, 1592754341.157636, 1592754341.157648, 1592754346.628817, 1592754346.914112, 1592754346.914114]
default length sequence: [171, -1370, -1024]
default timestamp sequence: [1592754332.516003, 1592754333.506533, 1592754341.157636]
extension: {'tls.handshake.extensions_server_name': ['', '', '', 'api.vk.com', '', '', '', '', '', '', '']}
Flow ('1592754322_clear.pcap', 'tcp', '3') info:
src ip: 10.82.8.58
dst ip: 87.240.137.206
sport: 48944
dport: 443
payload lengths : [171, -1208]
payload timestamps: [1592754344.451481, 1592754344.451491]
ip packets lengths: [60, -52, 40, 211, -40, -1248, 52, 52, 52, -40, 40]
ip packets timestamps: [1592754329.508604, 1592754344.451468, 1592754344.451471, 1592754344.451481, 1592754344.451487, 1592754344.451491, 1592754344.451494, 1592754346.326589, 1592754346.628819, 1592754346.914107, 1592754346.91411]
default length sequence: [171, -1208]
default timestamp sequence: [1592754344.451481, 1592754344.451491]
extension: {'tls.handshake.extensions_server_name': ['', '', '', 'api.vk.com', '', '', '', '', '', '', '']}
Flow ('1592754322_clear.pcap', 'tcp', '12') info:
src ip: 10.82.8.58
dst ip: 95.142.206.2
sport: 40001
dport: 443
payload lengths : [180, -1370, -1233]
payload timestamps: [1592754342.15773, 1592754343.802529, 1592754346.628824]
ip packets lengths: [60, -52, 40, 220, -1410, 52, 40, -1273, 40, 40]
ip packets timestamps: [1592754341.157658, 1592754342.157711, 1592754342.15772, 1592754342.15773, 1592754343.802529, 1592754343.802537, 1592754346.326723, 1592754346.628824, 1592754346.628826, 1592754346.914098]
default length sequence: [180, -1370, -1233]
default timestamp sequence: [1592754342.15773, 1592754343.802529, 1592754346.628824]
extension: {'tls.handshake.extensions_server_name': ['', '', '', 'sun6-16.userapi.com', '', '', '', '', '', '']}
Flow ('1592754322_clear.pcap', 'tcp', '13') info:
src ip: 10.82.8.58
dst ip: 95.142.206.2
sport: 40000
dport: 443
payload lengths : [180, -1232]
payload timestamps: [1592754344.451241, 1592754347.906631]
ip packets lengths: [60, -52, 40, 220, -40, 40, -1272, 40]
ip packets timestamps: [1592754341.157667, 1592754343.802553, 1592754343.80256, 1592754344.451241, 1592754344.451464, 1592754346.914105, 1592754347.906631, 1592754347.906653]
default length sequence: [180, -1232]
default timestamp sequence: [1592754344.451241, 1592754347.906631]
extension: {'tls.handshake.extensions_server_name': ['', '', '', 'sun6-16.userapi.com', '', '', '', '']}

```

