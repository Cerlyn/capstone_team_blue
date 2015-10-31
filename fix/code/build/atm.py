#!/usr/bin/python

# ATM Program
# Team Blue
# Coursera Capstone
# BIBIFI Fall 2015


import os.path
import signal
import ssl
import sys
import urllib3
from common_utils import CommonUtils


def SIGALRMhandler(signum, frame):
    CommonUtils.atm_protocol_error_exit('TIMEOUT')

signal.signal(signal.SIGALRM, SIGALRMhandler)


class ATM:
    def __init__(self):
        self._common_utils = CommonUtils('ATM')
        self.atm_protocol_error_exit = \
            self._common_utils.atm_protocol_error_exit
        self.error_exit = self._common_utils.error_exit
        self._common_utils.parse_opts()

    def read_cardfile(self, card_filename):
        cardhandle = file(card_filename, 'r')
        card_data = cardhandle.readline().rstrip()
        cardhandle.close()
        return card_data

    def write_cardfile(self, card_filename, card_data):
        cardhandle = file(card_filename, 'w')
        cardhandle.write(card_data)
        cardhandle.close()

    def run(self):
        global tempcafile

        utils = self._common_utils
        transactiontype = utils.get_transactiontype()

        card_filename = utils.get_cardfilename()
        card_data = ""

        if transactiontype != 'N':
            if card_filename is not None and os.path.isfile(card_filename):
                try:
                    card_data = self.read_cardfile(card_filename)
                except Exception:
                    self.error_exit('Error loading ATM card')
            else:
                self.error_exit('Card file not found to load')
        params = {}
        if transactiontype == 'N':
            params['action'] = 'new'
            params['account'] = utils.get_account()
            params['amount'] = utils.get_transactionamount()
        elif transactiontype == 'G':
            params['action'] = 'balance'
            params['account'] = utils.get_account()
            params['card'] = card_data
        elif transactiontype == 'D':
            params['action'] = 'deposit'
            params['account'] = utils.get_account()
            params['amount'] = utils.get_transactionamount()
            params['card'] = card_data
        elif transactiontype == 'W':
            params['action'] = 'withdraw'
            params['account'] = utils.get_account()
            params['amount'] = utils.get_transactionamount()
            params['card'] = card_data
        else:
            self.error_exit('Unknown transaction type - should never get here')

        clientcertfile = self._common_utils.get_authfilename()
        cacertfile = clientcertfile  # Last item; only cert with CA:TRUE set

        signal.alarm(10)

        try:
            # We are using IPs, but certificates prefer names
            # Override the SSL processing to look for our desired name
            atmserverhostname = 'atmserver.bank.example.com'
            httpsclient = urllib3.HTTPSConnectionPool(host=utils.get_ipaddress(),
                                                      port=utils.get_ipport(),
                                                      maxsize=1,
                                                      ca_certs=cacertfile,
                                                      cert_reqs=ssl.CERT_REQUIRED,
                                                      cert_file=clientcertfile,
                                                      ssl_version=ssl.PROTOCOL_TLSv1_2,
                                                      retries=0,
                                                      assert_hostname=atmserverhostname)
            response = httpsclient.request('GET', '/atm.cgi', params)

        except urllib3.exceptions.SSLError:
            self.atm_protocol_error_exit('SSL Communication failure')
        except Exception:
            self.error_exit('Unknown Communication failure')

        signal.alarm(0)

        if response.status != 200:
            self.error_exit('Remote error')

        response_data = response.data
        responselines = response_data.split('\n')

        if transactiontype == 'N':
            if len(responselines) == 1:
                self.error_exit('No card info provided')
            if os.path.exists(card_filename) is False:
                self.write_cardfile(card_filename, responselines[1] + '\n')
            else:
                self.error_exit('Card file found-cannot overwrite')

        sys.stdout.write(responselines[0] + '\n')
        sys.stdout.flush()


if __name__ == "__main__":
    myatm = ATM()
    myatm.run()
