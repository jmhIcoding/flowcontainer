__author__ = 'jmh'
import flowcontainer,os
from flowcontainer import extractor

user_agent = "http.user_agent"
host = "http.host"
uri = "http.request.full_uri"
cookie = "http.cookie"
file_data = "http.file_data"

def pcap_http_parser(pfile):
    extension=[user_agent, host, uri, cookie, file_data ]
    http_flows = extractor.extract(infile=pfile,
                      filter="http",
                      extension=extension)
    flows = []
    for each in http_flows:
        flow ={'pcapname': os.path.basename(pfile) }
        flow["src_ip"] = http_flows[each].src
        flow["sport"] = http_flows[each].sport
        flow["dst_ip"] = http_flows[each].dst
        flow["dport"] = http_flows[each].dport
        flow["protocol"] = http_flows[each].protocol
        flow['ext_proto'] =http_flows[each].ext_protocol
        flow["start"] = http_flows[each].time_start
        flow["end"] = http_flows[each].time_end

        if user_agent in http_flows[each].extension:
            flow[user_agent]= http_flows[each].extension[user_agent][0][0]
        if uri in http_flows[each].extension:
            flow[uri] = http_flows[each].extension[uri][0][0]
        if host in http_flows[each].extension:
            flow[host] = http_flows[each].extension[host][0][0]

        if cookie in http_flows[each].extension:
            flow[cookie] = http_flows[each].extension[cookie][0][0]

        if file_data in http_flows[each].extension:
            #flow[cookie] = http_flows[each].extension[cookie][0][0]
            flow[file_data] = http_flows[each].extension[file_data]
        flows.append(flow)
    return flows

if __name__ == '__main__':
   http_flow =  pcap_http_parser("../nat.pcap")
   for flow in http_flow:
       print(flow)
   import  json
   with open("http_flow_nat.json","w") as fp:
       json.dump(http_flow, fp)
