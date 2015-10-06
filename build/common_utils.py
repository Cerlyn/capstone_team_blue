import sys
import getopt
import re
from decimal import Decimal


class CommonUtils:
    def __init__(self, mode):
        # Parameters stored in CommonUtils are from the command-line
        # and for the Bank, may not be for the current transaction
        self._port = 3000
        self._account = None
        self._transactionType = None
        self._transactionAmount = None
        self._authFilename = "bank.auth"
        self._cardFilename = None

        if mode not in ('ATM', 'Bank'):
            self.error_exit("common_utils initialized in unknown mode")
        self._mode = mode

        if mode == 'ATM':
            self._ipaddr = '127.0.0.1'
        else:
            self._ipaddr = '0.0.0.0'  # Listening address per IRC clarification
        return None

    # Used in ATM client when protocol error or timeout occurs
    @staticmethod
    def atm_protocol_error_exit(message=None):
        if message:
            # May need to comment out STDERR output for contest scoring system
            # Although in theory it should be ignored
            sys.stderr.write(message + "\n")
            sys.stderr.flush()
            sys.exit(63)

    @staticmethod
    def error_exit(message=None):
        if message:
            # May need to comment out STDERR output for contest scoring system
            # Although in theory it should be ignored
            sys.stderr.write(message + "\n")
            sys.stderr.flush()
            sys.exit(255)

    @staticmethod
    def valid_accountstr(test_account):
        if (len(test_account) < 1) or (len(test_account) > 250):
            return False

        if re.match('[_\-\.0-9a-z]+$', test_account) == None:
            return False

        return True

    # Cannot be static because it references a variable
    @staticmethod
    def valid_currency(test_amount):
        # Maximum amount a user may specify to use during a transaction
        _MAXINPUTBALANCE = Decimal(4294967295.99)

        if re.match('([0-9]|[1-9][0-9]{0,9})\.\d\d$', test_amount) == None:
            return False

        if Decimal(test_amount) > _MAXINPUTBALANCE:
            return False

        return True

    @staticmethod
    def valid_intstr(test_integer):
        if re.match('0$|[1-9][0-9]*$', test_integer) == None:
            return False
        else:
            return True

    # Crude IPv4 check per the spec
    @staticmethod
    def valid_ipv4str(test_ipv4):
        if re.match('([0-9]|[1-9][0-9]{0,2})\.([0-9]|[1-9][0-9]{0,2})\.([0-9]|[1-9][0-9]{0,2})\.([0-9]|[1-9][0-9]{0,2})$',  # nopep8
                    test_ipv4) == None:
            return False

        octets = test_ipv4.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False

        return True

    @staticmethod
    def valid_filenamestr(test_filename):
        if (len(test_filename) < 1) or (len(test_filename) > 255):
            return False

        if (test_filename == '.') or (test_filename == '..'):
            return False

        if re.match('[_\-\.0-9a-z]+$', test_filename) == None:
            return False

        return True

    # Parses incoming arguments according to what get_opts allows
    # Does an initial pass per POSIX notes in and some contest spec features
    # To ensure nothing is violated
    #
    # mode is either 'ATM' or 'Bank'
    def parse_opts(self):
        if self._mode == 'ATM':
            getopt_spec = 's:i:p:c:a:n:d:w:g'
        else:  # Bank mode
            getopt_spec = 'p:s:'

        try:
            opts, otherargs = getopt.getopt(sys.argv[1:], getopt_spec)
        except Exception as e:
            self.error_exit(str(e.msg))

        if len(otherargs) > 0:
            self.error_exit("Bare arguments present")

        # ATM Mode: Check for arguments which exclude each other
        if self._mode == 'ATM':
            optflags = tuple(x[0] for x in opts)
            countedmodes = optflags.count('-n')  # New
            countedmodes += optflags.count('-d')  # Deposit
            countedmodes += optflags.count('-w')  # Withdraw
            countedmodes += optflags.count('-g')  # Get balance
            if countedmodes != 1:
                self.error_exit("Exactly one ATM transaction required")

            if optflags.count('-a') != 1:
                self.error_exit("Account to use must be specified once")

        # Parse all arguments, verify all values
        parsedops = []
        for opt, val in opts:
            if parsedops.count(opt) > 0:
                self.error_exit("Parameter specified twice")
            parsedops.append(opt)

            if len(val) > 4096:
                self.error_exit("Argument exceeds POSIX length")

            # Common arguments (Bank and ATM)
            if opt == '-p':  # Port
                if self.valid_intstr(val) == False:
                    self.error_exit("Port not an integer")

                if len(val) > 5:  # 65535
                    self.error_exit("Port too high (str)")

                self._port = int(val)
                if (self._port > 65535) or (self._port < 1024):
                    self.error_exit("Port out of range")

            elif opt == '-s':  # Auth file
                if self.valid_filenamestr(val) == False:
                    self.error_exit("Auth file is not a valid filename")

                self._authFilename = val

            # Below here are ATM client specific arguments
            elif opt == '-i':  # IP Address
                if self.valid_ipv4str(val) == False:
                    self.error_exit("Invalid IP Address")
                self._ipaddr = val

            elif opt == '-a':  # Account
                if self.valid_accountstr(val) == False:
                    self.error_exit("Invalid account name")
                self._account = val

            elif opt == '-c':  # Card file
                if self.valid_filenamestr(val) == False:
                    self.error_exit("Card file is not a valid filename")

                self._cardFilename = val

            elif opt == '-g':  # Get Balance
                self._transactionType = "G"

            elif opt == '-d':  # Deposit
                if self.valid_currency(val) == False:
                    self.error_exit("Invalid deposit amount")
                self._transactionType = "D"
                self._transactionAmount = Decimal(val)

            elif opt == '-w':  # Withdraw
                if self.valid_currency(val) == False:
                    self.error_exit("Invalid withdrawal amount")
                self._transactionType = "W"
                self._transactionAmount = Decimal(val)

            elif opt == '-n':  # New Account
                if self.valid_currency(val) == False:
                    self.error_exit("Invalid new account balance")
                self._transactionType = "N"
                self._transactionAmount = Decimal(val)

        # Set defaults for undefined items that are mode specific
        if self._mode == 'ATM':
            if self._cardFilename is None:
                self._cardFilename = self._account + ".card"

    def get_authfilename(self):
        return self._authFilename

    def get_account(self):
        return self._account

    def get_ipaddress(self):
        return self._ipaddr

    def get_ipport(self):
        return self._port

    def get_transactionamount(self):
        return self._transactionAmount

    def get_transactiontype(self):
        return self._transactionType
