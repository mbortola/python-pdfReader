__author__ = 'michele'

from pdfrw import PdfReader
from pyasn1.type import univ
from pyasn1.codec.ber import encoder, decoder
import array

if __name__ == "__main__":
    reader = PdfReader('/home/michele/Downloads/Signature-P-B-LT-2.pdf')

    keys = reader.keys()
    dss = reader.Root.DSS

    # PDFArray
    ocsps=dss.OCSPs
    # PDFArray
    certs=dss.Certs

    for cert in certs:
        # ascii decode
        byte_stream = array.array('B', cert.stream)
        # hex encode
        byte_strem_2 = [elem.encode('hex') for elem in cert.stream]

    print keys

    decoder.decode(b'\x02\x01\x0c', asn1Spec=univ.Integer())
    ## asn1 test

    substrate = encoder.encode(univ.Boolean(True))
    print decoder.decode(substrate)
