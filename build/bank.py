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


class ParameterException(Exception):
    pass


class MySSLSocket(ssl.SSLSocket):
    # Override the default accept handler to catch negotiation/MITM errors
    def accept(self):
        newsock, addr = socket.socket.accept(self)
        try:
            newsock = self.context.wrap_socket(newsock,
                        do_handshake_on_connect=self.do_handshake_on_connect,
                        suppress_ragged_eofs=self.suppress_ragged_eofs,
                        server_side=True)
        except Exception as e:
            sys.stdout.write("protocol_error\n")
            sys.stdout.flush()
            raise e
        return newsock, addr


class Vault():
    def __init__(self):
        self._accounts = {}
        self._randgen = SystemRandom()

    def adduser(self, user, balance):
        global BANKVAULT_THREADLOCK
        if user in self._accounts:
            raise ParameterException('User exists')
        if CommonUtils.valid_accountstr(user) == False:
            raise ParameterException('Invalid user')
        if CommonUtils.valid_currency(balance) == False:
            raise ParameterException('Invalid balance')
        if Decimal(balance) < 10.00:
            raise ParameterException('Initial deposit too low')
        BANKVAULT_THREADLOCK.acquire()
        try:
            self._accounts[user] = {}
            self._accounts[user]['balance'] = Decimal(balance)
            newcard = self._randgen.randint(1, sys.maxint)
            self._accounts[user]['card'] = str(newcard)
        except Exception as e:
            raise e
        finally:
            BANKVAULT_THREADLOCK.release()
        result = '{{"initial_balance": {0!s},"account": "{1}"}}\n{2}\n'.format(
                                                            Decimal(balance),
                                                            user, str(newcard))
        return result

    def getbalance(self, user, card):
        global BANKVAULT_THREADLOCK
        balance = None
        BANKVAULT_THREADLOCK.acquire()
        try:
            if user not in self._accounts:
                raise ParameterException('Authentication failure')
            if self._accounts[user]['card'] != card:
                raise ParameterException('Authentication failure')

            balance = self._accounts[user]['balance']
        except Exception as e:
            raise e
        finally:
            BANKVAULT_THREADLOCK.release()
        result = '{{"balance": {0!s},"account": "{1}"}}\n'.format(
                                                            Decimal(balance),
                                                            user)
        return result

    def deposit(self, user, card, amount):
        global BANKVAULT_THREADLOCK
        BANKVAULT_THREADLOCK.acquire()
        try:
            if user not in self._accounts:
                raise ParameterException('Authentication failure')
            if self._accounts[user]['card'] != card:
                raise ParameterException('Authentication failure')

            self._accounts[user]['balance'] = self._accounts[user]['balance'] \
                + Decimal(amount)
        except Exception as e:
            raise e
        finally:
            BANKVAULT_THREADLOCK.release()
        result = '{{"deposit": {0!s},"account": "{1}"}}\n'.format(
                                                            Decimal(amount),
                                                            user)
        return result

    def withdraw(self, user, card, amount):
        global BANKVAULT_THREADLOCK
        BANKVAULT_THREADLOCK.acquire()
        try:
            if user not in self._accounts:
                raise ParameterException('Authentication failure')
            if self._accounts[user]['card'] != card:
                raise ParameterException('Authentication failure')

            decimalamount = Decimal(amount)
            if (self._accounts[user]['balance'] - decimalamount) < Decimal(0):
                raise ParameterException('Insufficient funds')
            self._accounts[user]['balance'] = self._accounts[user]['balance'] \
                - decimalamount
        except Exception as e:
            raise e
        finally:
            BANKVAULT_THREADLOCK.release()
        result = '{{"withdraw": {0!s},"account": "{1}"}}\n'.format(
                                                            Decimal(amount),
                                                            user)
        return result


class TLSHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.timeout = 10
        try:
            BaseHTTPRequestHandler.__init__(self, request, client_address,
                                            server)
        except ssl.SSLError:
            sys.stdout.write("protocol_error\n")
            sys.stdout.flush()

    # Do not do default logging of messages to STDERR
    def log_message(self, logformat, *args):
        # BaseHTTPRequestHandler.log_message(self, logformat, *args)
        return

    # Override default error logger as well
    def log_error(self, logformat, *args):
        # BaseHTTPRequestHandler.log_error(self, logformat, *args)
        return

    def fail_request(self, logtext):
        self.send_response(500)
        self.send_header("Content-type", "text/plain")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-control", "no-cache")
        self.end_headers()
        self.wfile.write("request_failed\n")
        self.log_error('request_failed')

    def do_GET(self):
        self.connection.settimeout(10.0)
        # Parse URL query parameters, error out if invalid
        # FIXME: Move everything to POST once ATM-side implemented

        response_to_client = ""

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

            account = queryitems['account'][0]
            if CommonUtils.valid_accountstr(account) == False:
                raise Exception("Invalid parameters")

            amount = None
            if (action != 'balance'):
                amount = queryitems['amount'][0]
                if CommonUtils.valid_currency(amount) == False:
                    raise Exception("Invalid parameters")

            card = None
            if (action != 'new'):
                card = queryitems['card'][0]
                if (card is None) or (card == ""):
                    raise Exception("Invalid parameters")
            elif (action == 'new') and (card in queryitems):
                raise Exception("Invalid parameters")

            # After validation completes above, process the request
            if action == 'new':
                response_to_client = BANKVAULT.adduser(account, amount)
            elif action == 'balance':
                response_to_client = BANKVAULT.getbalance(account, card)
            elif action == 'deposit':
                response_to_client = BANKVAULT.deposit(account, card, amount)
            elif action == 'withdraw':
                response_to_client = BANKVAULT.withdraw(account, card, amount)
        except ParameterException:  # ATM supplied something incorrect
            self.fail_request("REQUEST FAILED")
            return
        except Exception:
            sys.stdout.write("protocol_error\n")
            sys.stdout.flush()
            self.fail_request("REQUEST FAILED")
            return

        # FIXME: Parse POST parameters
        # Validate supplied parameters/combinations (POST items)

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-control", "no-cache")
        self.end_headers()
        self.wfile.write(response_to_client)
        sys.stdout.write(response_to_client.split("\n")[0] + "\n")
        sys.stdout.flush()


class TLSHTTPServer(HTTPServer):
        def __init__(self, address, port, tlscertificate, tlsprivkey):
            socket.setdefaulttimeout(10.0)
            BaseServer.__init__(self, (address, port), TLSHandler)
            self.socket = MySSLSocket(socket.socket(self.address_family,
                                                    self.socket_type),
                                      ssl_version=ssl.PROTOCOL_TLSv1_2,
                                      certfile=TLStempfile.name,
                                      ca_certs=TLStempfile.name,
                                      cert_reqs=ssl.CERT_REQUIRED,
                                      server_side=True,
                                      suppress_ragged_eofs=False
                                      )

            self.server_bind()
            self.server_activate()

        def run(self):
            try:
                self.serve_forever()
            except KeyboardInterrupt:
                pass


class Threading_TLSHTTPServer(ThreadingMixIn, TLSHTTPServer):
    def handle_timeout(self):
        # HTTPServer.handle_timeout(self)
        sys.stdout.write("protocol_error")
        sys.stdout.flush()


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
            crypto.X509Extension("subjectAltName", True, "DNS:ca.bank.example.com"),
            crypto.X509ExtensionType("keyUsage", True, "keyCertSign, cRLSign"),
            crypto.X509ExtensionType("subjectKeyIdentifier", False, "hash",
                                     subject=self._certauthority),
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
            crypto.X509Extension("subjectAltName", True, "DNS:atmserver.bank.example.com"),
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
        tlsServer = Threading_TLSHTTPServer(self._common_utils.get_ipaddress(),
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
