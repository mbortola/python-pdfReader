import base64

import binascii

__author__ = 'michele'

from pdfrw import PdfReader
from pyasn1.type import univ
from pyasn1.codec.ber import encoder, decoder
import array

if __name__ == "__main__":
    #reader = PdfReader('/home/yyi9343/projects/python/personal/python-pdfReader/Signature-P-B-LT-2.pdf')
    reader = PdfReader('/home/yyi9343/projects/python/personal/python-pdfReader/Documento_firmato.pdf')
    dss = reader.Root.DSS

    # PDFArray
    ocsps=dss.OCSPs
    # PDFArray
    certs=dss.Certs

    for cert in certs:
        byte_stream = [elem.encode('hex') for elem in cert.stream]

    encoded = base64.b64encode(''.join([binascii.unhexlify(e) for e in byte_stream]))
    print encoded
    ## asn1 test

    substrate = encoder.encode(univ.Boolean(True))
    print decoder.decode(substrate)
