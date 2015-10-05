#!/usr/bin/python

# Bank Program
# Team Blue
# Coursera Capstone
# BIBIFI Fall 2015

import sys
import socket
import signal
import tempfile
import ssl
from OpenSSL import crypto
from common_utils import CommonUtils
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn, BaseServer

TLStempfile = None


def SIGTERMhandler(signum, frame):
    try:
        global TLStempfile
        if TLStempfile is not None:
            TLStempfile.close()  # Force deletion if possible
    except Exception:
        pass  # Program being requested to close
    finally:
        sys.exit(0)

signal.signal(signal.SIGTERM, SIGTERMhandler)


class TLSHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.timeout = 10
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_GET(self):
        self.connection.settimeout(10)
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("Hello World\n")


class TLSHTTPServer(HTTPServer, ThreadingMixIn):
        def __init__(self, address, port, tlscertificate, tlsprivkey):
            BaseServer.__init__(self, (address, port), TLSHandler)
            self.socket = ssl.SSLSocket(socket.socket(self.address_family,
                                                      self.socket_type),
                                        ssl_version=ssl.PROTOCOL_TLSv1_2,
                                        certfile=TLStempfile.name,
                                        server_side=True
                                        )
            self.server_bind()
            self.server_activate()

        def run(self):
            try:
                self.serve_forever()
            except KeyboardInterrupt:
                pass


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
        global TLStempfile

        self._tlsprivatekey = crypto.PKey()
        self._tlsprivatekey.generate_key(crypto.TYPE_RSA, 2048)

        certreq = crypto.X509Req()
        certreq.get_subject().CN = "atmserver.bank.example.com"
        certreq.set_pubkey(self._tlsprivatekey)
        certreq.sign(self._tlsprivatekey, "sha256")

        self._tlscert = crypto.X509()
        self._tlscert.set_subject(certreq.get_subject())
        self._tlscert.set_serial_number(self._certauthoritynextserial)
        self._tlscert.set_issuer(self._certauthority.get_subject())
        self._tlscert.gmtime_adj_notBefore(0)
        self._tlscert.gmtime_adj_notAfter(86400*365*3)  # under CA's lifetime
        self._tlscert.set_pubkey(certreq.get_pubkey())
        self._tlscert.add_extensions([
            crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
            crypto.X509ExtensionType("extendedKeyUsage", True, "serverAuth"),
        ])
        self._tlscert.sign(self._certauthorityprivatekey, "sha256")
        self._certauthoritynextserial = self._certauthoritynextserial + 1

        tlsfile = tempfile.NamedTemporaryFile()
        tlsfile.file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,
                                                  self._tlsprivatekey))
        tlsfile.file.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                   self._tlscert))
        tlsfile.file.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                   self._certauthority))
        tlsfile.file.flush()
        TLStempfile = tlsfile
        # Closing the file/program will destroy this temporary file

    def start_webserver(self):
        tlsServer = TLSHTTPServer(self._common_utils.get_ipaddress(),
                                  self._common_utils.get_ipport(),
                                  self._tlscert, self._tlsprivatekey)
        sys.stdout.write("Ready\n")  # FIXME: should be 'created\n'
        sys.stdout.flush()
        tlsServer.run()

    def run(self):
        self.setup_ca()
        self.setup_webcrypto()
        self.setup_atmcrypto()
        # FIXME: NEED TO WRITE ATM TICKET TO FILE
        # Start mutlithreading
        self.start_webserver()


if __name__ == "__main__":
    mybank = Bank()
    try:
        mybank.run()
    except KeyboardInterrupt:
        pass
