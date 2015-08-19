# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from oscrypto._win import tls


con = tls.TLSSocket('www.howsmyssl.com', 443)
print(con.cipher_suite)
con.write(b'GET /a/check HTTP/1.1\r\nHost: www.howsmyssl.com\r\nAccept: */*\r\nUser-Agent: oscrypto 0.10.1\r\n\r\n')
print(con.certificate.subject.human_friendly)
a = con.read()
print(a)

print()

con = tls.TLSSocket('www.google.com', 443)
print(con.cipher_suite)
con.write(b'GET / HTTP/1.1\r\nHost: www.google.com\r\nAccept: */*\r\nUser-Agent: oscrypto 0.10.1\r\n\r\n')
print(con.certificate.subject.human_friendly)
a = con.read()
print(a)

print()

con = tls.TLSSocket('packagecontrol.io', 443)
print(con.cipher_suite)
con.write(b'GET / HTTP/1.1\r\nHost: packagecontrol.io\r\nAccept: */*\r\nUser-Agent: oscrypto 0.10.1\r\n\r\n')
print(con.certificate.subject.human_friendly)
a = con.read()
print(a)
