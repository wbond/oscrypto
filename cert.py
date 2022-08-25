import asn1crypto.pem
import asn1crypto.x509
import oscrypto.asymmetric

with open('cert.pem', 'rb') as f:
  pem_bytes = f.read()

_, _, der_bytes = asn1crypto.pem.unarmor(pem_bytes)
cert = asn1crypto.x509.Certificate.load(der_bytes)
key_object = oscrypto.asymmetric.load_certificate(cert)
print(key_object.algorithm)
