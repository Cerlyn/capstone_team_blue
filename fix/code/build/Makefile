# Makefile for Team_Blue
# Coursera Captsone - Build It Break It Fix It - Fall 2015

# The spec for the project says
# "The executables must be able to be run from any working directory."
# So this is a bit more complicated and ugly than it should be

# Since Coursera's updated Linux VM has binfmt_misc configured for Python
# we directly execute Python bytecode without risking recompilation  

PYTHON=/usr/bin/python

all: PLAINTEXT=0
all: bank atm

all_plaintext: PLAINTEXT=1
all_plaintext: bank atm


bank: big_bank.py
	if [ $(PLAINTEXT) -eq 0 ] ; then $(PYTHON) -m compileall big_bank.py ; fi
	if [ $(PLAINTEXT) -eq 0 ] ; then cp big_bank.pyc bank ; fi
	if [ $(PLAINTEXT) -eq 1 ] ; then cp big_bank.py bank ; fi
	chmod 755 bank 

atm: big_atm.py	
	if [ $(PLAINTEXT) -eq 0 ] ; then $(PYTHON) -m compileall big_atm.py ; fi
	if [ $(PLAINTEXT) -eq 0 ] ; then cp big_atm.pyc atm ; fi
	if [ $(PLAINTEXT) -eq 1 ] ; then cp big_atm.py atm ; fi
	chmod 755 atm

big_bank.py:
	echo "#!/usr/bin/python" > big_bank.py
	cat common_utils.py bank.py | grep -v 'from common_utils' >> big_bank.py
	chmod 755 big_bank.py
	
big_atm.py:
	echo "#!/usr/bin/python" > big_atm.py
	cat common_utils.py atm.py | grep -v 'from common_utils' >> big_atm.py
	chmod 755 big_atm.py

clean:
	rm -f *.pyc *.pyo big_bank.py big_atm.py bank atm
