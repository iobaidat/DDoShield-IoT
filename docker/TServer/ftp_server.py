#!/usr/bin/env python3

# pip install pyftpdlib
# sudo apt-get install python3-pyftpdlib

# start server:
# sudo -E env PATH=$PATH ./1.py

# client:
# wget -r -l 10 --ftp-user='user' --ftp-password='123456' ftp://127.0.0.1:21/*
# or:
# curl --insecure ftp://127.0.0.1:21/1.py --user user:123456 -o /home/iobaidat/Desktop/1.py

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import os, sys

def main(IP):

	# Instantiate a dummy authorizer for managing 'virtual' users
	authorizer = DummyAuthorizer()

	dir_ftp = '/var/www/html/' # os.getcwd()
	print('Files directory: ',dir_ftp)

	# Define a new user having full r/w permissions and a read-only
	# anonymous user
	authorizer.add_user('user', '123456', dir_ftp, perm='elradfmwMT')
	
	authorizer.add_anonymous(dir_ftp)


	handler = FTPHandler
	handler.authorizer = authorizer

	server = FTPServer((IP, 21), handler)
	server.serve_forever()

if __name__ == '__main__':
	# Minimal configuration - allow to pass IP in configuration
	if len(sys.argv) < 2:
	   print("\nUSAGE : " + sys.argv[0] +
	            " <IPv4>")
	   sys.exit()

	IP = sys.argv[1]
	try:
		main(IP)
	except KeyboardInterrupt:
		sys.exit(0)