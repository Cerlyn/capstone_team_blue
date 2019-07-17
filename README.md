# README #

This repository contains the First-place entry for the Fall 2015 "Built it Break it Fix it" contest in the Coursera Builder category.

This (or a close cousin) likely is the Python program which "made use of the SSL PKI infrastructure" as mentioned in the [published paper on the contest](https://arxiv.org/abs/1606.01881). 

## Introduction ##

The [Build it Break it Fix it](https://builditbreakit.org/) contest was a series of programming contests.  Participants were encouraged to submit a secure software solution to a problem.  In this case, the challenge was to create a "bank" which could securely communicate and maintain accounts with an "ATM".

After creating a solution which passed a set of pre-provided functionality & performance tests, the participants would then attempt to break each other's solutions.  Seperate scores were assigned to the building and breaking phases of the contest.

After the breaks were disclosed, participants then had the opportunity to make repairs to partially regain points.

There were three categories of entrants:
* College Students
* [Coursera](https://www.coursera.org/) students taking this as the capstone class in a Cybersecurity specialization
* Cybersecurity Professionals (not eligible for prizes; primarily to help break things)

## Solution ##
This solution, written in Python, generates a central certificate authority which then signs separate SSL/TLS certificates for the bank and ATM.  The bank and ATM only trust certificates signed by this CA.

The bank's information is held in a secure tempfile, while the ATM's certificate is handed to it per the contest specification.  They then communicate over HTTPS.

Extensive error handling as well as log eating/redirection was done to meet contest specifications.

## Compiling ##
This solution can be compiled by using the Makefile in the build/ subdirectory.  Bytecode-compiled python variants are made by default; but plaintext scripts are available by setting PLAINTEXT=1.

Alternatively, the bank.py and atm.py scripts can be run on their own as long as common_utils.py is present.
