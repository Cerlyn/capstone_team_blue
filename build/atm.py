#!/usr/bin/python

# ATM Program
# Team Blue
# Coursera Capstone
# BIBIFI Fall 2015


from common_utils import CommonUtils


class ATM:
    def __init__(self):
        self._common_utils = CommonUtils('ATM')
        self.atm_protocol_error_exit = \
            self._common_utils.atm_protocol_error_exit
        self.error_exit = self._common_utils.error_exit
        self._common_utils.parse_opts()

    def run(self):
        pass


if __name__ == "__main__":
    myatm = ATM()
    myatm.run()
