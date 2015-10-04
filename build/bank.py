#!/usr/bin/python

# Bank Program
# Team Blue
# Coursera Capstone
# BIBIFI Fall 2015

from OpenSSL import SSL, crypto
from common_utils import CommonUtils


class Bank:
    def __init__(self):
        self._common_utils = CommonUtils('Bank')
        self.error_exit = self._common_utils.error_exit
        self._common_utils.parse_opts()

        # For CA
        self._certauthorityprivatekey = None
        self._certauthority = None
        self._certauthoritynextserial = None
        # For web server
        self._tlscert = None
        self._tlsprivatekey = None

    def setup_ca(self):
        self._certauthorityprivatekey = crypto.PKey()
        # Key sizes based on survey of bank web sites & CA Authorities
        # Code based on http://docs.ganeti.org/ganeti/2.9/html/design-x509-ca.html
        self._certauthorityprivatekey.generate_key(crypto.TYPE_RSA, 2048)
        self._certauthority = crypto.X509()
        self._certauthority.set_version(3)
        self._certauthority.set_serial_number(1)
        self._certauthority.get_subject().CN = "ca.bank.example.com"
        self._certauthority.gmtime_adj_notBefore(0)
        self._certauthority.gmtime_adj_notAfter(86400 * 365 * 5)  # ~5 years
        self._certauthority.set_issuer(self._certauthority.get_subject())
        self._certauthority.set_pubkey(self._certauthorityprivatekey)
        self._certauthority.add_extensions([
            crypto.X509Extension("basicConstraints", True,
                                 "CA:TRUE, pathlen:0"),
            crypto.X509ExtensionType("keyUsage", True, "keyCertSign, cRLSign"),
            crypto.X509ExtensionType("subjectKeyIdentifier", False, "hash",
                                     subject=self._certauthority)
        ])
        self._certauthority.sign(self._certauthorityprivatekey, "sha256")
        self._certauthoritynextserial = 2

    def setup_atmcrypto(self):
        atmkey = crypto.PKey()
        atmkey.generate_key(crypto.TYPE_RSA, 2048)

        certreq = crypto.X509Req()
        certreq.get_subject().CN = "atm-machine.bank.example.com"
        certreq.set_pubkey(self._tlsprivatekey)
        certreq.sign(self._tlsprivatekey, "sha256")

        self._tlscert = crypto.X509()
        self._tlscert.set_subject(certreq.get_subject())
        self._tlscert.set_serial_number(self._certauthoritynextserial)
        self._tlscert.gmtime_adj_notBefore(0)
        self._tlscert.gmtime_adj_notAfter(86400*365*3)  # under CA's lifetime
        self._tlscert.set_pubkey(certreq.get_pubkey())
        self._tlscert.add_extensions([
            crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
            crypto.X509ExtensionType("extendedKeyUsage", True, "clientAuth"),
        ])
        self._tlscert.sign(self._certauthorityprivatekey, "sha256")
        self._certauthoritynextserial = self._certauthoritynextserial + 1

    def setup_webcrypto(self):
        self._tlsprivatekey = crypto.PKey()
        self._tlsprivatekey.generate_key(crypto.TYPE_RSA, 2048)

        certreq = crypto.X509Req()
        certreq.get_subject().CN = "atmserver.bank.example.com"
        certreq.set_pubkey(self._tlsprivatekey)
        certreq.sign(self._tlsprivatekey, "sha256")

        self._tlscert = crypto.X509()
        self._tlscert.set_subject(certreq.get_subject())
        self._tlscert.set_serial_number(self._certauthoritynextserial)
        self._tlscert.gmtime_adj_notBefore(0)
        self._tlscert.gmtime_adj_notAfter(86400*365*3)  # under CA's lifetime
        self._tlscert.set_pubkey(certreq.get_pubkey())
        self._tlscert.add_extensions([
            crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
            crypto.X509ExtensionType("extendedKeyUsage", True, "serverAuth"),
        ])
        self._tlscert.sign(self._certauthorityprivatekey, "sha256")
        self._certauthoritynextserial = self._certauthoritynextserial + 1

    def run(self):
        self.setup_ca()
        self.setup_webcrypto()
        self.setup_atmcrypto()


if __name__ == "__main__":
    mybank = Bank()
    mybank.run()
