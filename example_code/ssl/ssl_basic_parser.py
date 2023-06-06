__author__ = 'jmh'
import flowcontainer, os
from flowcontainer import extractor
import easy_x509
sni = "tls.handshake.extensions_server_name"
cipher_suites = "tls.handshake.ciphersuite"
alpn="tls.handshake.extensions_alpn_str"
x509cert ="tls.handshake.certificate"

def pcap_ssl_parser(pfile):
    extensions = [sni, cipher_suites, alpn, x509cert]
    ssl_flows = extractor.extract(infile=pfile,
                                  filter="tls",
                                  extension=extensions)
    flows = []
    for each in ssl_flows:
        flow ={'pcapname': os.path.basename(pfile) }
        flow["src_ip"] =  ssl_flows[each].src
        flow["sport"] =   ssl_flows[each].sport
        flow["dst_ip"] =  ssl_flows[each].dst
        flow["dport"] =   ssl_flows[each].dport
        flow["protocol"] = ssl_flows[each].protocol
        flow['ext_proto'] =ssl_flows[each].ext_protocol
        flow["start"] =    ssl_flows[each].time_start
        flow["end"] =    ssl_flows[each].time_end

        if sni in ssl_flows[each].extension:
            flow["sni"] = ssl_flows[each].extension[sni][0][0]

        if cipher_suites in ssl_flows[each].extension:
            flow["cipher_suites"] = "|".join(
                [ssl_flows[each].extension[cipher_suites][i][0] for i in range(len(ssl_flows[each].extension[cipher_suites]))])

        if alpn in ssl_flows[each].extension:
            flow["alpn"] = "|".join(
                [ssl_flows[each].extension[alpn][i][0] for i in range(len(ssl_flows[each].extension[alpn]))])

        if x509cert in ssl_flows[each].extension:
            certificate_hex = ",".join(
                [ssl_flows[each].extension[x509cert][i][0] for i in range(len(ssl_flows[each].extension[x509cert]))]
            )
            certificate_hexs = certificate_hex.split(',')
            certs = []
            for cert in certificate_hexs:
                try:
                    certs.append(easy_x509.x509_parser(cert))
                except BaseException as exp:
                    print(exp)

            flow['certificates'] = certs

        flows.append(flow)
    return flows

if __name__ == '__main__':
   flows =  pcap_ssl_parser("../tid_ssl.pcap")
   for flow in flows:
       print(flow)
   import  json
   with open("ssl_flow_tid8.json","w") as fp:
       json.dump(flows, fp)