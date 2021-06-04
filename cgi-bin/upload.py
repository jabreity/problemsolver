#!/usr/bin/python
# -*- coding: UTF8 -*-
import cgi
import cgitb
import uuid
import sys
# sys.path.append("/Users/jason/PycharmProjects/ProblemSetExplorer/static/magic")
import magic

cgitb.enable()
form = cgi.FieldStorage()

# file inbound, write out to disk
if 'fileToUpload' in form:

    identifier = str(uuid.uuid1())
    fileContents = form['fileToUpload'].value
    fileName = "uploads/" + identifier

    try:
        f = open(fileName, "wb")
        f.write(fileContents)
        f.close()
    except:
        print('Content-type: text/html\n')
        print("""{
    "success": false,
    "file": """ + '"http://localhost/cgi-bin/upload.py?file=' + identifier + '"' + """
}""")
    else:
        print('Content-type: text/html\n')
        print("""{
    "success": true,
    "file": """ + '"http://localhost/cgi-bin/upload.py?file=' + identifier + '"' + """
}""")

else:
    # file output, read out to stdio
    if 'file' in form:
        try:
            # unprotected print(form['file'].value)
            # Validate input is valid UUID
            val = uuid.UUID(form['file'].value, version=1)
            fileRead = 'uploads/' + str(val)
            # print('Content-type: application/jpeg\n')
            # print('Content-type: application/jpeg\n')

        except ValueError:
            print('not a UUID')
        else:
            try:
                with open(fileRead) as f:
                    print('Content-type: ' + magic.from_file(fileRead, mime=True) + '\n')
                    print(f.read())
                    f.close()
            except FileNotFoundError:
                print('file not found')
            except ValueError:
                print('Value Error')
