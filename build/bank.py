#!/usr/bin/python

# Bank Program
# Team Blue
# Coursera Capstone
# BIBIFI Fall 2015

import ssl
import socket
import signal
import sys
import tempfile
import threading
import urlparse
from os import path
from OpenSSL import crypto
from common_utils import CommonUtils
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn, BaseServer
from decimal import Decimal
from random import SystemRandom

TLStempfile = None
BANKVAULT = None
BANKVAULT_THREADLOCK = None


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


class Vault():
    def __init__(self):
        self._accounts = {}
        self._randgen = SystemRandom()

    def adduser(self, user, balance):
        if user not in self._accounts:
            raise Exception('User exists')
        if CommonUtils.valid_accountstr(user) == False:
            raise Exception('Invalid user')
        if CommonUtils.valid_currency(balance) == False:
            raise Exception('Invalid balance')
        BANKVAULT_THREADLOCK.acquire()
        self._accounts[user] = {}
        self._accounts[user]['balance'] = Decimal(balance)
        newcard = self._randgen.randint(1, sys.maxint)
        self._accounts[user]['card'] = newcard
        BANKVAULT_THREADLOCK.release()
        return newcard

    def getbalance(self, user, card):
        BANKVAULT_THREADLOCK.acquire()
        if user not in self._accounts:
            raise Exception('Authentication failure')
        if self._accounts[user]['card'] != card:
            raise Exception('Authentication failure')

        balance = self._accounts['balance']
        BANKVAULT_THREADLOCK.release()
        return balance

    def deposit(self, user, card, amount):
        BANKVAULT_THREADLOCK.acquire()
        if user not in self._accounts:
            raise Exception('Authentication failure')
        if self._accounts[user]['card'] != card:
            raise Exception('Authentication failure')

        self._accounts[user]['balance'] = self._accounts[user]['balance'] + \
            Decimal(amount)
        BANKVAULT_THREADLOCK.release()

    def withrdaw(self, user, card, amount):
        BANKVAULT_THREADLOCK.acquire()
        if user not in self._accounts:
            raise Exception('Authentication failure')
        if self._accounts[user]['card'] != card:
            raise Exception('Authentication failure')

        decimalamount = Decimal(amount)
        if (self._accounts[user]['balance'] - decimalamount) < Decimal(0):
            raise Exception('Insufficient funds')
        self._accounts[user]['balance'] = self._accounts[user]['balance'] - \
            decimalamount


class TLSHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.timeout = 10
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    # Do not do default logging of messages to STDERR
    def log_message(self, logformat, *args):
        # BaseHTTPRequestHandler.log_message(self, logformat, *args)
        return

    # Override default error logger to provide spec-required error message
    def log_error(self, logformat, *args):
        # BaseHTTPRequestHandler.log_error(self, logformat, *args)
        sys.stdout.write("protocol_error\n")
        sys.stdout.flush()

    def fail_request(self, logtext):
        self.send_response(500)
        self.send_header("Content-type", "text/plain")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-control", "no-cache")
        self.end_headers()
        self.wfile.write("request_not_handled\n")
        self.log_error('failed_request')

    def do_GET(self):
        self.connection.settimeout(10)
        # Parse URL query parameters, error out if invalid
        # FIXME: Move everything to POST once ATM-side implemented
        try:
            urlparts = urlparse.urlparse(self.path)
            path = urlparts.path
            if path != "/atm.cgi":
                raise Exception("Invalid path")
            query = urlparts.query
            queryitems = urlparse.parse_qs(query)
            action = queryitems['action'][0]

            if action not in ('new', 'balance', 'deposit', 'withdraw'):
                raise Exception("Invalid action")

            if (action == 'balance') and ('amount' in queryitems):
                raise Exception("Invalid parameters")

            if CommonUtils.valid_currency(queryitems['amount'][0]) == False:
                raise Exception("Invalid parameters")
            # FIXME: Add card verification

        except Exception:
            self.fail_request("PARSE EXCEPTION")
            return

        # FIXME: Parse POST parameters
        # Validate supplied parameters/combinations (POST items)

        # FIXME: Do required action instead of just responding back
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-control", "no-cache")
        self.end_headers()
        self.wfile.write("Hello World\n")
        self.wfile.write(path)


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
        certreq.set_pubkey(atmkey)
        certreq.sign(atmkey, "sha256")

        atmcert = crypto.X509()
        atmcert.set_subject(certreq.get_subject())
        atmcert.set_serial_number(self._certauthoritynextserial)
        atmcert.set_issuer(self._certauthority.get_subject())
        atmcert.gmtime_adj_notBefore(0)
        atmcert.gmtime_adj_notAfter(86400*365*3)  # under CA's lifetime
        atmcert.set_pubkey(certreq.get_pubkey())
        atmcert.add_extensions([
            crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
            crypto.X509ExtensionType("extendedKeyUsage", True, "clientAuth"),
        ])
        atmcert.sign(self._certauthorityprivatekey, "sha256")
        self._certauthoritynextserial = self._certauthoritynextserial + 1

        if path.exists(self._common_utils.get_authfilename()):
            self.error_exit('Auth file already exists (race check)')
        outfile = file(self._common_utils.get_authfilename(), 'w')
        outfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,
                                             atmkey))
        outfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                              atmcert))
        outfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                              self._certauthority))
        outfile.close()

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
        # Since we infinitely loop in the webserver
        # Notify that the card was created as late as possible to avoid races
        # with the test infrastructure
        sys.stdout.write("created\n")
        sys.stdout.flush()
        tlsServer.run()

    def run(self):
        global BANKVAULT
        global BANKVAULT_THREADLOCK
        BANKVAULT = Vault()
        BANKVAULT_THREADLOCK = threading.Lock()
        self.setup_ca()
        self.setup_webcrypto()
        self.setup_atmcrypto()

        # FIXME: NEED TO WRITE ATM TICKET TO FILE
        # Start mutlithreading
        try:
            self.start_webserver()
        except socket.error as e:
            self.error_exit(str(e))


if __name__ == "__main__":
    mybank = Bank()
    try:
        mybank.run()
    except KeyboardInterrupt:
        pass
