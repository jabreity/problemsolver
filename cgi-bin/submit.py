#!/usr/bin/python3
# -*- coding: UTF8 -*-
import cgi
# import cgitb

# cgitb.enable()
form = cgi.FieldStorage()

# students
    # student.py for write, studentName=USER
    # Database stores generated UUID:USER in dictionary
    # Student logs in, receives crypt reference to a UUID generated ephemerally

# crypt
    # APPLICATION ONLY
    # GET crypt.py for read, student=crypt
    # Returns UUID

# session keeper
    # remove crypt references existing or containing dates beyond a certain point
    # tame unruly session creation by way of MAC ID ban list

# fraud minder
    # report invalid UUID:IMAGE GET/POST requests
    # ban untamed posters

# student submit write
    # POST submit.py?problem=2.4.3.4&question=1 for write, content='foobyfoo' (student=crypt)
    # creates a solution by calling upload.py, receiving a UUID
    # Stores a mapping between UUID:User and solution UUID
    # Submit receives a solution UUID, creates a dictionary pairing user:solution and pset:question


# if 'problem' and 'question' and 'content' in form:
if 'content' in form:
    # a = str(form['problem'].value) + ":" + str(form['question'].value)
    k = {"2.4.3.4:1": str(form['content'].value)}
    # dictionary append upload and 'problem:question':UUID
    with open('database/' + '2.4.3.4', 'a') as f:
        f.write(str(k) + "\n")
        f.close()


