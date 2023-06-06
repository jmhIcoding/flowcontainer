from traffic_parser import Parser
from traffic_parser.http.http_basic_parser import pcap_http_parser
import json
class HTTP_Parser(Parser):
    def __init__(self):
        super(HTTP_Parser, self).__init__()
        ## http 表列

        self.sql = "INSERT INTO traffic_http VALUES (%s, %s,%s, %s, %s, %s,%s, %s, %s, " \
                   "%s, %s, %s, %s, %s)"
    def pcap_parse(self, pfile):
        http_flows = pcap_http_parser(pfile=pfile)
        return http_flows
    def insert_db(self, http_flows):
        values = []
        for flow in http_flows:
            value = (flow['src_ip'], flow['sport'], flow['dst_ip'], flow['dport'], flow['protocol'], flow['ext_proto'], flow['pcapname'], flow['start'],flow['end'],
            flow['http.user_agent'].encode('utf8').decode('utf8') if 'http.user_agent' in flow else '',
            flow['http.request.full_uri'] if 'http.request.full_uri' in flow else '',
            flow['http.host'] if 'http.host' in flow else '',
            flow['http.cookie'] if 'http.cookie' in flow else '',
            json.dumps(flow['http.file_data'] if 'http.file_data' in flow else []))
            values.append(value)
            #print(value)
        self.insert_sql_batch(self.sql, values)

if __name__ == '__main__':
    http_parser = HTTP_Parser()
    http_flows = http_parser.pcap_parse(pfile='../tid_http.pcap')
    http_parser.insert_db(http_flows)
    #import pprint
    #pprint.pprint(http_flows)
