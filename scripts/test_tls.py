# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

# Make the script import oscrypto from this folder, not the system
import sys
from os import path
parent_dir = path.dirname(path.dirname(path.abspath(__file__)))
sys.path.insert(0, parent_dir)

from oscrypto import tls


def read_html(domain, url_path='/', context=None):
    con = tls.TLSSocket(domain, 443, context=context)
    print('Domain:\n  %s' % domain)
    print('Protocol:\n  %s' % con.protocol)
    print('Cipher Suite:\n  %s' % con.cipher_suite)
    print('Compression:\n  %s' % repr(con.compression))
    print('Session ID:\n  %s' % repr(con.session_id))
    print('Session Ticket:\n  %s' % repr(con.session_ticket))
    print('Certificate:\n  %s' % con.certificate.subject.human_friendly)
    request = 'GET %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nUser-Agent: oscrypto 0.10.1\r\n\r\n' % (url_path, domain)
    con.write(request.encode('ascii'))

    lines = []
    line = con.read_line()
    while line.strip() != b'':
        lines.append(line)
        line = con.read_line()

    print('Headers:')
    headers = {}
    for index, line in enumerate(lines):
        if index == 0:
            print('  %s' % line.decode('ascii').rstrip())
            continue
        line = line.decode('ascii')
        name, value = line.rstrip().split(':', 1)
        name = name.strip()
        value = value.strip()
        headers[name] = value
        print('  %s: %s' % (name, value))

    output = b''
    if 'Transfer-Encoding' in headers and headers['Transfer-Encoding'] == 'chunked':
        while True:
            next_line = con.read_line().decode('ascii').strip()
            num_bytes = int(next_line, 16)
            if num_bytes == 0:
                break
            output += con.read_exactly(num_bytes)
            _ = con.read_line()
    else:
        num_bytes = int(headers['Content-Length'])
        output += con.read_exactly(num_bytes)

    print('HTML:')
    print(repr(output))

    print()
    con.shutdown()

goog_context = tls.TLSContext()

read_html('www.google.com', context=goog_context)
read_html('www.google.com', url_path='/music', context=goog_context)
read_html('www.howsmyssl.com', url_path='/a/check')
read_html('packagecontrol.io')
