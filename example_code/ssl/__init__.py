from traffic_parser import Parser
from traffic_parser.ssl.ssl_basic_parser import pcap_ssl_parser
import json
class SSL_Parser(Parser):
    def __init__(self):
        super(SSL_Parser, self).__init__()
        ## http 表列

        self.sql = "INSERT INTO traffic_ssl VALUES (%s, %s,%s, %s, %s, %s,%s, %s, %s, " \
                   "%s, %s, %s, %s)"
    def pcap_parse(self, pfile):
        ssl_flows = pcap_ssl_parser(pfile=pfile)
        return ssl_flows

    def insert_db(self, ssl_flows):
        values = []
        for flow in ssl_flows:
            value = (flow['src_ip'], flow['sport'], flow['dst_ip'], flow['dport'], flow['protocol'], flow['ext_proto'], flow['pcapname'], flow['start'],flow['end'],
            flow['sni'] if 'sni' in flow else '',
            flow['alpn'] if 'alpn' in flow else '',
            flow['cipher_suites'] if 'cipher_suites' in flow else '',
            json.dumps(flow['certificates'] if 'certificates' in flow else []))
            values.append(value)
            #print(value)
        self.insert_sql_batch(self.sql, values)

if __name__ == '__main__':
    ssl_parser = SSL_Parser()
    ssl_flows = ssl_parser.pcap_parse(pfile='../nat.pcap')
    ssl_parser.insert_db(ssl_flows)
    import pprint
    #pprint.pprint(ssl_flows)
