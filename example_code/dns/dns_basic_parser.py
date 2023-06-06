__author__ = 'jmh'
import os
dns_query = "dns.qry.name"

dns_response_name = "dns.resp.name"
dns_response_type = "dns.resp.type"
dns_response_class = "dns.resp.class"
dns_response_address = "dns.a"
dns_response_name_server = "dns.ns"
dns_response_cname = "dns.cname"


typeid2str={
    "5":"CNAME",
    "1":"A",
    "2":"NS"
}
from flowcontainer import extractor
def dns_basic_parser(pfile):
    extension = [dns_query,
                 dns_response_name,
                 dns_response_type,
                 dns_response_class,
                 dns_response_address,
                 dns_response_name_server,
                 dns_response_cname
    ]
    dns_flows = extractor.extract(infile=pfile,
                                  filter="dns",
                                  extension=extension
            )
    flows =[]
    for each in dns_flows:
        try:
            ##print(dns_flows[each])
            flow ={'pcapname': os.path.basename(pfile) }
            flow["src_ip"] = dns_flows[each].src
            flow["sport"] = dns_flows[each].sport
            flow["dst_ip"] = dns_flows[each].dst
            flow["dport"] = dns_flows[each].dport
            flow["protocol"] = dns_flows[each].protocol
            flow['ext_proto'] =dns_flows[each].ext_protocol
            flow["start"] = int(dns_flows[each].time_start)
            flow["end"] = int(dns_flows[each].time_end)
            names = []
            types = []
            classes = []
            addresses = []
            name_servers = []
            cnames = []

            if dns_response_name in dns_flows[each].extension:
                names  = dns_flows[each].extension[dns_response_name][0][0].split(",")

            if dns_response_type in dns_flows[each].extension:
                types = dns_flows[each].extension[dns_response_type][0][0].split(",")

            if dns_response_class in dns_flows[each].extension:
                classes = dns_flows[each].extension[dns_response_class][0][0].split(",")

            if dns_response_address in dns_flows[each].extension:
                addresses = dns_flows[each].extension[dns_response_address][0][0].split(",")

            if dns_response_name_server in dns_flows[each].extension:
                name_servers = dns_flows[each].extension[dns_response_name_server][0][0].split(",")

            if dns_response_cname in dns_flows[each].extension:
                cnames = dns_flows[each].extension[dns_response_cname][0][0].split(",")

            records = []
            names_id = 0
            addresses_id = 0
            cnames_id = 0
            name_servers_id = 0


            for _value in types:
                if _value not in ['1', '5', '2']:
                    continue
                    #只过滤a记录, cname记录 和ns记录
                real_type = typeid2str[_value]
                record={
                    "NAME": names[names_id],
                    "TYPE": real_type,
                }
                names_id += 1

                if _value == '1':
                    # a记录
                    record["ADDRESS"] = addresses[addresses_id]
                    addresses_id += 1
                if _value == '2':
                    # NS记录
                    record["NAMESEVER"] = name_servers[name_servers_id]
                    name_servers_id +=1
                if _value =='5':
                    # CNAME记录
                    record["CNAME"] = cnames[cnames_id]
                    cnames_id += 1
                records.append(record)

            flow['dns_records'] = records
            if len(records)>0:
                flows.append(flow)
        except BaseException as exp:
            print(exp)
            print(dns_flows[each])
    return flows


if __name__ == '__main__':
    dns_flows = dns_basic_parser(pfile="../tid_dns.pcap")
    for each in dns_flows:
        print(each)

    import  json
    with open("dns_flow_tid.json","w") as fp:
       json.dump(dns_flows, fp)