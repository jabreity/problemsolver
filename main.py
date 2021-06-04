#!/usr/bin/python3
import os
import sys
from http.server import HTTPServer, CGIHTTPRequestHandler
webdir = '.'    # Where your HTML and CGI live
port = 80     # Where your http://server lives

if len(sys.argv) > 1:
    webdir = sys.argv[1]
if len(sys.argv) > 2:
    port = int(sys.argv[2])
print('webdir "%s", port %s' % (webdir, port))

os.chdir(webdir)  # HTML Root
srvraddr = ('', port)
srvrobj = HTTPServer(srvraddr, CGIHTTPRequestHandler)
srvrobj.serve_forever()
