#!/usr/bin/python

# Bank Program
# Team Blue
# Coursera Capstone
# BIBIFI Fall 2015

from common_utils import CommonUtils


class Bank:
    def __init__(self):
        self._common_utils = CommonUtils('Bank')
        self.error_exit = self._common_utils.error_exit
        self._common_utils.parse_opts()

    def run(self):
        pass


if __name__ == "__main__":
    mybank = Bank()
    mybank.run()
