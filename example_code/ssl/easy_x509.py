__author__ = 'dk'
#x509证书解析

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except BaseException as exp:
    raise BaseException('Please install cryptography library: pip3 install cryptography -i https://mirrors.aliyun.com/pypi/simple/')
def bytes_to_string(bytes):
    return str(bytes, 'utf-8')

def x509name_to_json(x509_name):
    json = { }
    for attribute in x509_name:
        name = attribute.oid._name
        value = attribute.value
        json[name]=value
    return json

def x509_parser(cert_hex):
    cert = bytes.fromhex(cert_hex.replace(':',''))
    cert = x509.load_der_x509_certificate(cert, default_backend())
    rst = {
        'issuer':x509name_to_json(cert.issuer),
        'subject':x509name_to_json(cert.subject),
        #'extensions':cert.extensions,
        'not_valid_before':str(cert.not_valid_before),
        'not_valid_after':str(cert.not_valid_after),
        'seriral_number':cert.serial_number,
        "version": cert.version.name,
    }
    return rst


