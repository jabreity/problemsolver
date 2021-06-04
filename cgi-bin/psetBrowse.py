#!/usr/bin/python3
# -*- coding: UTF8 -*-
import re
import cgi
from collections import OrderedDict
import ast

problems = OrderedDict([('2.4.3.4  Exercises \n',
                         ['1.  Use man to look at the man page for one of your preferred commands. \n',
                          '2.  Use man to look for a keyword related to file compression. \n',
                          '3.  Use which to locate the pwd command on your Kali virtual machine. \n',
                          '4.  Use locate to locate wce32.exe on your Kali virtual machine. \n',
                          '5.  Use find to identify any file (not directory) modified in the last day, NOT owned by the root user and execute ls -l on them. Chaining/piping commands is NOT allowed! \n']),
                        ('2.6.6.1  Exercises \n',
                         ['2.5  Managing Kali Linux Services \n', '(Reporting is not required for these exercises) \n',
                          '1.  Take a snapshot of your Kali virtual machine (optional). \n',
                          '2.  Search for a tool not currently installed in Kali. \n', '3.  Install the tool. \n',
                          '4.  Remove the tool. \n']), ('3.1.3.2  Exercises \n', ['2.7  Wrapping Up \n',
                                                                                  "(reverse-i-search)`ca': cat /etc/lsb-release  \n",
                                                                                  'Listing 37 - Exploring the reverse-i-search facility \n',
                                                                                  '1. Inspect your bash history and use history expansion to re-run a command from it. \n',
                                                                                  '2. Execute different commands of your choice and experiment browsing the history through the shortcuts as well as the reverse-i-search facility. \n']),
                        ('3.2.5.1  Exercises \n', ['3.2  Piping and Redirection \n',
                                                   '1.  Use the cat command in conjunction with sort to reorder the content of the /etc/passwd file on your Kali Linux system. \n',
                                                   '2.  Redirect the output of the previous exercise to a file of your choice in your home directory. \n']),
                        ('3.3.5.1  Exercises \n', ['3.3  Text Searching and Manipulation \n',
                                                   '1.  Using /etc/passwd, extract the user and home directory fields for all users on your Kali machine for which the shell is set to /bin/false. Make sure you use a Bash one-liner to print the output to the screen. The output should look similar to Listing 53 below: \n',
                                                   '2.  Copy the /etc/passwd file to your home directory (/home/kali). \n',
                                                   '3.  Use cat in a one-liner to print the output of the /kali/passwd and replace all instances of the “Gnome Display Manager” string with “GDM”. \n']), (
                        '3.5.3.1  Exercises \n',
                        ['3.4  Editing Files from the Command Line \n',
                         '1.  Download the archive from the following URL https://offensive-security.com/pwk-...\n',
                         '2.  This archive contains the results of scanning the same target machine at different times. \n',
                         'Extract the archive and see if you can spot the differences by diffing the scans. \n']), (
                        '3.6.3.1  Exercises \n', ['3.6  Managing Processes \n',
                                                  '1.  Find files that have changed on your Kali virtual machine within the past 7 days by running a specific command in the background. \n',
                                                  '2.  Re-run the previous command and suspend it; once suspended, background it. \n',
                                                  '3.  Bring the previous background job into the foreground. \n',
                                                  '4.  Start the Firefox browser on your Kali system. Use ps and grep to identify Firefox’s PID. \n',
                                                  '5.  Terminate Firefox from the command line using its PID. \n']), (
                        '3.7.2.1  Exercises \n', ['3.7  File and Command Monitoring \n',
                                                  '1.  Start your apache2 web service and access it locally while monitoring its access.log file in \n',
                                                  '2.  Use a combination of watch and ps to monitor the most CPU-intensive processes on your Kali machine in a terminal window; launch different applications to see how the list changes in real time. \n']), ('3.8.3.1  Exercise \n',
                                                                         ['3.8  Downloading Files \n',
                                                                          '1.  Download the PoC code for an exploit from https://www.exploit-db.com using curl, wget, and axel, saving each download with a different name. \n']),
                        ('3.9.3.1  Exercises \n',
                         ['3.9  Customizing the Bash Environment \n',
                          '1.  Create an alias named “..” to change to the parent directory and make it persistent across \n',
                          '2.  Permanently configure the history command to store 10000 entries and include the full date \n']),
                        ('4.1.4.3  Exercises \n',
                         ['3.10 Wrapping Up \n', '(Reporting is not required for these exercises) \n',
                          '2.  Use Netcat to create a: \n', 'a.  Reverse shell from Kali to Windows. \n',
                          'b.  Reverse shell from Windows to Kali. \n',
                          'c.  Bind shell on Kali. Use your Windows system to connect to it. \n',
                          'd.  Bind shell on Windows. Use your Kali machine to connect to it. \n',
                          '3.  Transfer a file from your Kali machine to Windows and vice versa. \n',
                          '4.  Conduct the exercises again with the firewall enabled on your Windows system. Adapt the exercises as necessary to work around the firewall protection and understand what portions of the exercise can no longer be completed successfully. \n']), ('4.2.4.1  Exercises \n',
                                                                                            ['4.2  Socat \n',
                                                                                             '1.  Use socat to transfer powercat.ps1 from your Kali machine to your Windows system. Keep the file on your system for use in the next section. \n',
                                                                                             '2.  Use socat to create an encrypted reverse shell from your Windows system to your Kali machine. \n',
                                                                                             '3.  Create an encrypted bind shell on your Windows system. Try to connect to it from Kali without encryption. Does it still work? \n',
                                                                                             '4.  Make an unencrypted socat bind shell on your Windows system. Connect to the shell using Netcat. Does it work? Note: If cmd.exe is not executing, research what other parameters you may need to pass to the EXEC option based on the error you receive. \n']),
                        ('4.3.8.1  Exercises \n', ['4.3  PowerShell and Powercat \n', 'Kali machine. \n',
                                                   '1.  Use PowerShell and powercat to create a reverse shell from your Windows system to your \n',
                                                   '2.  Use PowerShell and powercat to create a bind shell on your Windows system and connect to it from your Kali machine. Can you also use powercat to connect to it locally? \n',
                                                   '3.  Use powercat to generate an encoded payload and then have it executed through powershell. Have a reverse shell sent to your Kali machine, also create an encoded bind shell on your Windows system and use your Kali machine to connect to it. \n']),
                        ('4.4.5.1  Exercises \n', ['4.4  Wireshark \n',
                                                   '1.  Use Wireshark to capture network activity while attempting to connect to 10.11.1.217 on port 110 using Netcat, and then attempt to log into it. \n',
                                                   '2.  Read and understand the output. Where is the three-way handshake happening? Where is the connection closed? \n',
                                                   '3.  Follow the TCP stream to read the login attempt. \n',
                                                   '4.  Use the display filter to only monitor traffic on port 110. \n',
                                                   '5.  Run a new session, this time using the capture filter to only collect traffic on port 110. \n']),
                        ('4.5.3.1  Exercises \n', ['4.5  Tcpdump \n', 'flag might help. \n',
                                                   '1.  Use tcpdump to recreate the Wireshark exercise of capturing traffic on port 110. \n',
                                                   '2.  Use the -X flag to view the content of the packet. If data is truncated, investigate how the -s \n',
                                                   '3.  Find all ‘SYN’, ‘ACK’, and ‘RST’ packets in the password_cracking_filtered.pcap file. \n',
                                                   '4.  An alternative syntax is available in tcpdump where you can use a more user-friendly filter to display only ACK and PSH packets. Explore this syntax in the tcpdump manual by searching for “tcpflags”. Come up with an equivalent display filter using this syntax to filter ACK and PSH packets.  \n']), ('5.7.3.1  Exercises \n',
                                                                          ['4.6  Wrapping Up \n',
                                                                           '1.  Research Bash loops and write a short script to perform a ping sweep of your target IP range \n',
                                                                           '2.  Try to do the above exercise with a higher-level scripting language such as Python, Perl, or \n',
                                                                           '3.  Use the practical examples in this module to help you create a Bash script that extracts JavaScript files from the access_log.txt file (http://www.offensive-security.com/pwk-files/access_log.txt.gz). Make sure the file names DO NOT include the path, are unique, and are sorted. \n',
                                                                           '4.  Re-write the previous exercise in another language such as Python, Perl, or Ruby. \n']),
                        ('6.3.1.1  Exercise \n', ['5.8  Wrapping Up \n']), ('6.4.1.1  Exercises \n',
                                                                            ['6.4  Google Hacking \n',
                                                                             '1.  Who is the VP of Legal for MegaCorp One and what is their email address? \n',
                                                                             '2.  Use Google dorks (either your own or any from the GHDB) to search www.megacorpone.com for interesting documents. \n',
                                                                             '3.  What other MegaCorp One employees can you identify that are not listed on www.megacorpone.com? \n']),
                        ('6.5.1.1  Exercise \n', ['6.5  Netcraft \n']), ('6.6.1.1  Exercise \n', ['6.6  Recon-ng \n',
                                                                                                  '(Reporting is not required for this exercise) \n',
                                                                                                  '1. Gather information on MegaCorp One. \n',
                                                                                                  '2.  Take some time to explore other recon-ng modules. \n']),
                        ('6.7.1.1  Exercise \n', ['6.7  Open-Source Code \n']), ('6.12.1.1 Exercises \n',
                                                                                 ['6.8  Shodan \n',
                                                                                  '1.  Use theHarvester to enumerate emails addresses for megacorpone.com. \n',
                                                                                  '2.  Experiment with different data sources (-b). Which ones work best for you? \n']),
                        ('6.13.2.1 Exercise \n', ['6.12.2 \n', 'employees. \n',
                                                  '1.  Use any of the social media tools previously discussed to identify additional MegaCorp One \n']), ('7.1.6.3  Exercises \n', ['6.14 Stack Overflow \n',
                                                                                         '1.  Find the DNS servers for the megacorpone.com domain. \n',
                                                                                         '2.  Write a small script to attempt a zone transfer from megacorpone.com using a higher-level scripting language such as Python, Perl, or Ruby. \n',
                                                                                         '3.  Recreate the example above and use dnsrecon to attempt a zone transfer from megacorpone.com. \n']), (
                        '7.2.2.9  Exercises \n', ['7.2  Port Scanning \n',
                                                  '1.  Use Nmap to conduct a ping sweep of your target IP range and save the output to a file. Use grep to show machines that are online. \n',
                                                  '2.  Scan the IP addresses you found in exercise 1 for open webserver ports. Use Nmap to find the webserver and operating system versions. \n',
                                                  '3.  Use NSE scripts to scan the machines in the labs that are running the SMB service. \n',
                                                  '4.  Use Wireshark to capture a Nmap connect and UDP scan and compare it against the Netcat port scans. Are they the same or different? \n',
                                                  '5.  Use Wireshark to capture a Nmap SYN scan and compare it to a connect scan and identify the difference between them. \n']), ('7.3.2.1  Exercises \n',
                                                                                        ['7.2.3  Masscan \n',
                                                                                         '1.  Use Nmap to make a list of the SMB servers in the lab that are running Windows. \n',
                                                                                         '2.  Use NSE scripts to scan these systems for SMB vulnerabilities. \n',
                                                                                         '3.  Use nbtscan and enum4linux against these systems to identify the types of data you can obtain from different versions of Windows. \n']),
                        ('7.4.2.1  Exercises \n', ['7.4  NFS Enumeration \n']), ('7.5.1.1  Exercises \n',
                                                                                               ['7.5  SMTP Enumeration \n']),
                        ('7.6.3.6  Exercises \n', ['7.6  SNMP Enumeration \n']), ('8.2.4.2  Exercises \n',
                                                                                  ['7.7  Wrapping Up \n',
                                                                                   '1.  Follow the steps above to create your own unauthenticated scan of Gamma. \n',
                                                                                   '2.  Run the scan with Wireshark open and identify the steps the scanner performed to completed the scan. \n',
                                                                                   '3.  Review the results of the scan. \n']),
                        ('8.2.5.2  Exercises \n', ['8.2.5  Authenticated Scanning With Nessus \n',
                                                   '1.  Follow the steps above to create your own authenticated scan of your Debian client. \n',
                                                   '2.  Review the results of the scan. \n']), ('8.2.6.1  Exercises \n',
                                                                                                [
                                                                                                    '8.2.6  Scanning with Individual Nessus Plugins \n',
                                                                                                    '1.  Follow the steps above to create your own individual scan of Beta. \n',
                                                                                                    '2.  Run Wireshark or tcpdump during the individual scan. What other ports does Nessus scan? Why do you think Nessus scans other ports? \n',
                                                                                                    '3.  Review the results of the scan. \n']),
                        ('8.3.1.1  Exercise \n', ['8.3  Vulnerability Scanning with Nmap \n']), ('9.3.4.1  Exercise \n',
                                                                                                 ['8.4  Wrapping Up \n',
                                                                                                  '1.  Spend some time reviewing the applications available under the Web Application Analysis \n']), (
                        '9.4.1.3  Exercises \n',
                        ['9.4  Exploiting Web-based Vulnerabilities \n', 'machine. \n', '2. Insert a new user into the “users” table. \n']), ('9.4.2.5  Exercises \n',
                                                                            ['9.4.2  Cross-Site Scripting (XSS) \n',
                                                                             '1.  Exploit the XSS vulnerability in the sample application to get the admin cookie and hijack the session. Remember to use the PowerShell script on your Windows 10 lab machine to simulate the admin login. \n',
                                                                             '2.  Consider what other ways an XSS vulnerability in this application might be used for attacks. \n',
                                                                             '3.  Does this exploit attack the server or clients of the site? \n']),
                        ('9.4.3.2  Exercise \n', ['9.4.2.6  Other XSS Attack Vectors \n']), (
                        '9.4.4.5  Exercises \n', ['9.4.4  File Inclusion Vulnerabilities \n',
                                                  '1.  Obtain code execution through the use of the LFI attack. \n',
                                                  '2.  Use the code execution to obtain a full shell. \n']), (
                        '9.4.4.7  Exercises \n', ['9.4.4.6  Remote File Inclusion (RFI) \n',
                                                  '1.  Exploit the RFI vulnerability in the web application and get a shell. \n',
                                                  '2.  Using /menu2.php?file=current_menu as a starting point, use RFI to get a shell. \n',
                                                  '3.  Use one of the webshells included with Kali to get a shell on the Windows 10 target. \n']),
                        ('9.4.4.10 Exercises \n', ['9.4.4.8  Expanding Your Repertoire \n',
                                                   '1.  Exploit the LFI vulnerability using a PHP wrapper. \n',
                                                   '2.  Use a PHP wrapper to get a shell on your Windows 10 lab machine. \n']),
                        ('9.4.5.4  Exercises \n', ['9.4.5  SQL Injection \n', '1.  Interact with the MariaDB database and manually execute the commands required to authenticate to the application. Understand the vulnerability. \n',
                                                   '2.  SQL inject the username field to bypass the login process. \n',
                                                   '3.  Why is the username displayed like it is in the web application once the authentication \n',
                                                   '4.  Execute the SQL injection in the password field. Is the “LIMIT 1” necessary in the payload? \n',
                                                   'process is bypassed? \n', 'Why or why not? \n']), (
                        '9.4.5.9  Exercises \n', ['9.4.5.5  Enumerating the Database \n',
                                                  '1.  Enumerate the structure of the database using SQL injection. \n',
                                                  '2.  Understand how and why you can pull data from your injected commands and have it displayed on the screen. \n',
                                                  '3.  Extract all users and associated passwords from the database. \n']),
                        ('9.4.5.11 Exercises \n', ['9.4.5.10 From SQL Injection to Code Execution \n', '1.  execution. \n',
                                                   '2.  Turn the simple code execution into a full shell. \n']), (
                        '9.4.5.13 Exercises \n', ['9.4.5.12 Automating SQL Injection \n',
                                                  '1.  Use sqlmap to obtain a full dump of the database. \n',
                                                  '2.  Use sqlmap to obtain an interactive shell. \n']), (
                        '11.1.1.2 Exercises \n',
                        ['9.5  Extra Miles \n', '1.  Build the fuzzer and replicate the SyncBreeze crash. \n', '2. Inspect the content of other registers and stack memory. Does anything seem to be directly influenced by the fuzzing input? \n']), ('11.2.3.1 Exercises \n',
                                                                   ['11.2 Win32 Buffer Overflow Exploitation \n',
                                                                    '1.  Write a standalone script to replicate the crash. \n',
                                                                    '2.  Determine the offset within the input buffer to successfully control EIP. \n',
                                                                    '3.  Update your standalone script to place a unique value into EIP to ensure your offset is correct. \n']), ('11.2.5.1 Exercises \n',
                                                                                      ['11.2.4 \n',
                                                                                       '1.  Repeat the required steps in order to identify the bad characters that cannot be included in \n',
                                                                                       '2.  Why are these characters not allowed? How do these bad hex characters translate to ASCII? \n']),
                        ('11.2.7.1 Exercises \n',
                         ['11.2.6 \n', '1.  Locate the JMP ESP that is usable in the exploit. \n',
                          '2.  Update your PoC to include the discovered JMP ESP, set a breakpoint on it, and follow the execution to the placeholder shellcode. \n']), ('11.2.9.1 Exercises \n', ['11.2.8 \n',
                                                                                                     '1.  Update your PoC to include a working payload. \n',
                                                                                                     '2.  Attempt to execute your exploit without using a NOP sled and observe the decoder corrupting the stack. \n',
                                                                                                     '3.  Add a NOP sled to your PoC and obtain a shell from SyncBreeze. \n']), (
                        '12.2.1.2 Exercises \n', ['11.2.10 \n', '1.  Log in to your dedicated Linux client using the credentials you received. \n',
                                                  '2.  On your Kali machine, recreate the proof-of-concept code that crashes the Crossfire server. \n',
                                                  '3.  Attach the debugger to the Crossfire server, run the exploit against your Linux client, and confirm that the EIP register is overwritten by the malicious buffer. \n']),
                        ('12.3.1.1 Exercises \n', ['12.3 Controlling EIP \n',
                                                   '1.  Determine the correct buffer offset required to overwrite the return address on the stack. \n',
                                                   '2.  Update your stand-alone script to ensure your offset is correct. \n']),
                        ('12.5.1.1 Exercises \n', ['12.4 Locating Space for Our Shellcode \n',
                                                   '1.  Determine the opcodes required to generate a first stage shellcode using msf-nasm_shell. \n', '2.  Identify the bad characters that cannot be included in the payload and return address. \n']),
                        ('12.6.1.1 Exercises \n', ['12.6 Finding a Return Address \n',
                                                   '1.  Find a suitable assembly instruction address for the exploit using EDB. \n',
                                                   '2.  Include the first stage shellcode and return address instruction in your proof-of-concept and ensure that the first stage shellcode is working as expected by single stepping through it in the debugger. \n']), ('12.7.1.1 Exercises \n',
                                                                          ['12.7 Getting a Shell \n',
                                                                           '1.  Update your proof-of-concept to include a working payload. \n',
                                                                           '2.  Obtain a shell from the Crossfire application with and without a debugger. \n']),
                        ('13.1.2.3 Exercises \n',
                         ['12.8 Wrapping Up \n', 'Note: Reporting is not required for these exercises \n', '1.  Identify your public IP address. Using public information sources, see what you can learn about your IP address. If you don’t find anything on your specific IP address, try the class C it \n',
                          'is a part of. \n',
                          '2.  Compare what information you can gather about your home IP address to one gathered for your work IP address. Think about how an attacker could use the discovered information as part of an attack. \n',
                          '3.  Download the Fingerprint2 library and craft a web page similar to the one shown in the Client Fingerprinting section. Browse the web page from your Windows 10 lab machine and repeat the steps in order to collect the information extracted by the JavaScript library on your Kali web server. \n']), ('13.2.2.1 Exercises \n',
                                               ['13.2 Leveraging HTML Applications \n',
                                                '1.  Use msfvenom to generate a HTML Application and use it to compromise your Windows \n',
                                                '2. Is it possible to use the HTML Application attack against Microsoft Edge users, and if so, how? \n']), ('13.3.2.1 Exercise \n',
                                                              ['13.3 Exploiting Microsoft Office \n',
                                                               '1.  Use the PowerShell payload from the HTA attack to create a Word macro that sends a reverse shell to your Kali system. \n']), (
                        '13.3.3.1 Exercise \n', ['13.3.3 \n',
                                                 '1.  Use the PowerShell payload to create a batch file and embed it in a Microsoft Word document to send a reverse shell to your Kali system. \n']), (
                        '13.3.4.1 Exercises \n',
                        ['13.3.4 \n', 'document from the Internet. \n', 'shell to your Kali system. \n']), (
                        '14.3.1.1 Exercises \n', ['13.4 Wrapping Up \n',
                                                  '1.  Connect to your dedicated Linux client and start the vulnerable Apache James service using the /usr/local/james/bin/run.sh script. \n',
                                                  '2.  Enumerate the target using port scanning utilities and use information from the banners and Internet searches to determine the software running on the machine. \n',
                                                  '3.  Use the searchsploit tool to find exploits for this version on the online resources mentioned in this module. \n',
                                                  '4.  Launch the exploit and verify that the payload is executed upon logging in to the machine. \n',
                                                  '5.  Attempt to modify the payload variable in order to get a reverse shell on the target machine. \n']),
                        ('15.1.3.1 Exercises \n', ['14.4 Wrapping Up \n',
                                                   '1.  Locate the exploit discussed in this section using the searchsploit tool in Kali Linux. \n',
                                                   '2.  Install the mingw-w64 suite in Kali Linux and compile the exploit code. \n']),
                        ('15.1.4.1 Exercises \n', ['15.1.4 \n',
                                                   '1.  Modify the connection information in the exploit in order to target the SyncBreeze installation on your Windows client. \n',
                                                   '2.  Recompile the exploit and use Wireshark to confirm that the code successfully initiates a socket connection to your dedicated Windows client. \n']),
                        ('15.1.5.1 Exercise \n', ['15.1.5 \n',
                                                  '1.  Find any valid return address instruction and alter the one present in the original exploit. \n']),
                        ('15.1.6.1 Exercises \n', ['15.1.6 \n', 'characters of our exploit. \n',
                                                   '1.  Generate a reverse shell payload using msfvenom while taking into account the bad \n',
                                                   '2.  Replace the original payload with the newly generated one. \n',
                                                   '3.  Attach the debugger to the target process and set a breakpoint at the return address instruction. \n',
                                                   '4.  Compile the exploit and run it. Did you hit the breakpoint? \n']), ('15.1.7.1 Exercises \n',
                                                                ['15.1.7 \n',
                                                                 '1.  Fix the overflow buffer such that the EIP register will be overwritten by your chosen return \n',
                                                                 '2.  Install the ASX to MP3 Converter application located under the C:\\Tools\\fixing_exploits directory; download the exploit for ASX to MP3 Converter from EDB391 and edit it in order to get a shell on your dedicated Windows machine. \n']),
                        ('15.2.3.1 Exercises \n', ['15.2 Fixing Web Exploits \n',
                                                   '1.  Connect to your dedicated Linux lab client and start the apache2 service; the target web application is located under /var/www/https/. \n',
                                                   '2.  Modify the original exploit and set the base_url variable to the correct IP address of your dedicated Linux lab client as well as the protocol to HTTPS. \n',
                                                   '3.  Get familiar with the requests Python library and adjust your exploit accordingly to avoid SSL verification. \n',
                                                   '4.  Edit the username and password variables to match the ones from our test case (username “admin”, password “HUYfaw763”). \n',
                                                   '5.  Try to run the exploit against the Linux lab client, does it work? If not, try to explain why. \n']), ('15.2.4.1 Exercises \n', ['15.2.4 \n',
                                                                                          '1.  Observe the error that is generated when running the exploit. \n',
                                                                                          '2.  Attempt to troubleshoot the code and determine why the error occurs. \n',
                                                                                          '3.  Modify the exploit in order to avoid the error and run it against your dedicated Linux client. \n',
                                                                                          '4.  Verify that your exploit worked by attempting to execute the whoami command using the remote php shell. \n',
                                                                                          '5.  Attempt to obtain a fully interactive shell with this exploit. \n']),
                        ('16.1.3.2 Exercises \n',
                         ['15.3 Wrapping Up \n', '(Reporting is not required for these exercises) \n',
                          '1.  Start the Pure-FTPd FTP server on your Kali system, connect to it using the FTP client on the Debian lab VM, and observe how the interactive prompt works. \n',
                          '2.  Attempt to log in to the FTP server from a Netcat reverse shell and see what happens. \n',
                          '3.  Research alternatives methods to upgrade a non-interactive shell. \n']), (
                        '16.2.5.1 Exercises \n', ['16.2 Transferring Files with Windows Hosts \n',
                                                  '(Reporting is not required for these exercises) \n',
                                                  '1.  Use VBScript to transfer files in a non-interactive shell from Kali to Windows. \n',
                                                  '2.  Use PowerShell to transfer files in a non-interactive shell from Kali to Windows and vice versa. \n',
                                                  '3.  For PowerShell version 3 and above, which is present by default on Windows 8.1 and \n',
                                                  'Windows 10, the cmdlet Invoke-WebRequest403 was added. Try to make use of it in order to perform both upload and download requests to your Kali machine. \n',
                                                  '4.  Use TFTP to transfer files from a non-interactive shell from Kali to Windows. Note: If you encounter problems, first attempt the transfer process within an interactive shell and watch for issues that may cause problems in a non-interactive shell. \n']),
                        ('17.3.3.2 Exercises \n', ['16.3 Wrapping Up \n', 'of how it works. \n']), (
                        '17.3.3.4 Exercises \n', ['17.3.3.3 Shellter \n', 'antivirus. \n', '1. \n',
                                                  'Inject a meterpreter reverse shell payload in the WinRAR executable. \n',
                                                  '2.  Transfer the binary to your Windows client and ensure that it is not being detected by the \n',
                                                  '3.  Run the WinRAR installer and migrate your meterpreter shell to prevent a disconnect. \n',
                                                  '4.  Attempt to find different executables and inject malicious code into them using Shellter. \n']),
                        ('18.1.2.1 Exercises \n', ['17.4 Wrapping Up \n', '1.  Inspect your Windows and Linux clients by using the tools and commands presented in this section in order to get comfortable with manual local enumeration techniques. \n',
                                                   '2.  Experiment with different windows-privesc-check and unix_privesc_check options. \n']),
                        ('18.2.3.2 Exercise \n', ['18.2 Windows Privilege Escalation Examples \n', '1.  Log in to your Windows client as the admin user and attempt to bypass UAC using the application and technique covered above. \n']), (
                        '18.2.4.1 Exercises \n', ['18.2.4 \n', '1. Log in to your Windows client as an unprivileged user and attempt to elevate your privileges to SYSTEM using the above vulnerability and technique. \n',
                                                  '2.  Attempt to get a remote system shell rather than adding a malicious user. \n']),
                        ('18.3.2.1 Exercise \n', ['18.2.5 \n', '1. Log in to your Debian client as an unprivileged user and attempt to elevate your privileges to root using the above technique. \n']), ('18.3.3.1 Exercise \n',
                                                                                           ['18.3.3 \n', '1.  Log in to your Debian client with your student credentials and attempt to elevate your privileges by adding a superuser account to the /etc/passwd file. \n']),
                        ('19.1.1.1 Exercise \n', ['18.3.4 \n', '(Reporting is not required for this exercise) \n',
                                                  '1.  Use cewl to generate a custom wordlist from your company, school, or favorite website and examine the results. Do any of your passwords show up? \n']), (
                        '19.2.1.1 Exercise \n',
                        ['19.2 Brute Force Wordlists \n', '(Reporting is not required for this exercise) \n',
                         '1.  Add a user on your Kali system and specify a complex password for the account that includes lower and upper case letters, numbers, and special characters. Use both crunch rule patterns and pre-defined character-sets in order to generate a wordlist that include that user’s password. \n']), ('19.3.1.1 Exercises \n',
                                                   ['19.3 Common Network Service Attack Methods \n',
                                                    '(Reporting is not required for these exercises) \n',
                                                    '1.  Repeat the password attack against the htaccess protected folder. \n',
                                                    '2.  Create a password list containing your Windows client password and use that to perform a password attack again the SMB protocol on the Windows client. \n']),
                        ('19.3.2.1 Exercise \n', ['19.3.2 \n', '(Reporting is not required for these exercises) \n',
                                                  '1.  Create a password list containing your Windows client password and use that to repeat the above Crowbar password attack against the Windows client. \n']), (
                        '19.3.3.1 Exercise \n', ['19.3.3 \n', '(Reporting is not required for these exercises) \n',
                                                 '1.  Recreate the Hydra SSH attack against your Kali VM. \n']), (
                        '19.3.4.1 Exercises \n', ['19.3.4 \n', '(Reporting is not required for these exercises) \n',
                                                  '1.  Run the HTTP POST password attack against the web form on your Windows client. \n',
                                                  '2.  Perform a FTP password attack against the Pure-FTPd application on your local Kali Linux machine. \n']), ('19.4.1.1 Exercises \n',
                                                                    ['19.4 Leveraging Password Hashes \n',
                                                                     '(Reporting is not required for these exercises) \n',
                                                                     '1. Identify the password hash version used in your Kali system. \n',
                                                                     '2.  Use mimikatz to dump the password hashes from the SAM database on your Windows client. \n']), ('19.4.2.1 Exercises \n',
                                                                                      ['19.4.2 \n', 'client. \n',
                                                                                       '1.  Use Mimikatz to extract the password hash of an administrative user from the Windows \n',
                                                                                       '2.  Reuse the password hash to perform a pass-the-hash attack from your Kali system and obtain code execution on your Windows client. \n']),
                        ('19.4.3.1 Exercise \n', ['19.4.3 \n', '(Reporting is not required for this exercise) \n',
                                                  'hash using John the Ripper. \n']), ('20.1.1.1 Exercises \n',
                                                                                       ['19.5 Wrapping Up \n',
                                                                                        '1.  Connect to your dedicated Linux lab client and run the clear_rules.sh script from /root/port_forwarding_and_tunneling/ as root. \n',
                                                                                        '2.  Attempt to replicate the port-forwarding technique covered in the above scenario. \n']),
                        ('20.2.1.1 Exercises \n', ['20.2 SSH Tunneling \n',
                                                   '1.  Connect to your dedicated Linux lab client and run the clear_rules.sh script from /root/port_forwarding_and_tunneling/ as root. \n',
                                                   '2.  Run the ssh_local_port_forwarding.sh script from /root/port_forwarding_and_tunneling/ as root. \n',
                                                   '3.  Take note of the Linux client and Windows Server 2016 IP addresses shown in the Student Control Panel. \n',
                                                   '4.  Attempt to replicate the smbclient enumeration covered in the above scenario. \n']),
                        ('20.2.2.2 Exercises \n', ['20.2.2 \n',
                                                   '1.  Connect to your dedicated Linux lab client via SSH and run the clear_rules.sh script from /root/port_forwarding_and_tunneling/ as root. \n',
                                                   '2.  Close any SSH connections to your dedicated Linux lab client and then connect as the student account using rdesktop and run the ssh_remote_port_forward.sh script from /root/port_forwarding_and_tunneling/ as root. \n',
                                                   '3.  Attempt to replicate the SSH remote port forwarding covered in the above scenario and ensure that you can scan and interact with the MySQL service. \n']),
                        ('20.2.3.1 Exercises \n', ['20.2.3 \n',
                                                   '1.  Connect to your dedicated Linux lab client and run the clear_rules.sh script from /root/port_forwarding_and_tunneling/ as root. \n',
                                                   '2.  Take note of the Linux client and Windows Server 2016 IP addresses. \n',
                                                   '3.  Create a SOCKS4 proxy on your Kali machine, tunneling through the Linux target. \n',
                                                   '4.  Perform a successful nmap scan against the Windows Server 2016 machine through the proxy. \n',
                                                   '5.  Perform an nmap SYN scan through the tunnel. Does it work? Are the results accurate? \n']),
                        ('20.3.1.1 Exercises \n', ['20.3 PLINK.exe \n']), ('20.4.1.1 Exercise \n',
                                                                                         ['20.4 NETSH \n',
                                                                                          '1.  Obtain a reverse shell on your Windows lab client through the Sync Breeze vulnerability. \n',
                                                                                          '2.  Using the SYSTEM shell, attempt to replicate the port forwarding example using netsh. \n']), (
                        '20.5.1.1 Exercises \n', ['20.5 HTTPTunnel-ing Through Deep Packet Inspection \n',
                                                  '1.  Connect to your dedicated Linux lab client as the student account using rdesktop and run the http_tunneling.sh script from /root/port_forwarding_and_tunneling/ as root. \n',
                                                  '2.  Start the apache2 service and exploit the vulnerable web application hosted on port 443 (covered in a previous module) in order to get a reverse HTTP shell.599 \n',
                                                  '3.  Replicate the scenario demonstrated above using your dedicated clients. \n']),
                        ('21.2.1.1 Exercise \n', ['20.6 Wrapping Up \n',
                                                  '1.  Connect to your Windows 10 client and use net.exe to lookup users and groups in the \domain. See if you can discover any interesting users or groups. \n']),
                        ('21.2.2.1 Exercises \n', ['21.2.2 \n',
                                                   '1.  Modify the PowerShell script to only return members of the Domain Admins group. \n',
                                                   '2.  Modify the PowerShell script to return all computers in the domain. \n',
                                                   '3.  Add a filter to only return computers running Windows 10. \n']),
                        ('21.2.3.1 Exercises \n', ['21.2.3 \n',
                                                   '1.  Repeat the enumeration to uncover the relationship between Secret_Group, Nested_Group,and Another_Nested_Group. \n',
                                                   '2.  The script presented in this section required us to change the group name at each iteration. Adapt the script in order to unravel nested groups programmatically without knowing their names beforehand. \n', '634 \n']), ('21.2.4.1 Exercises \n',
                                                                                        ['21.2.4 \n',
                                                                                         '1.  Download and use PowerView to perform the same enumeration against the student VM while in the context of the Offsec account. \n',
                                                                                         '2.  Log in to the student VM with the Jeff_Admin account and perform a remote desktop login to the domain controller using the Jeff_Admin account. Next, execute the Get-NetLoggedOn function on the student VM to discover logged-in users on the domain controller while in the context of the Jeff_Admin account. \n',
                                                                                         '3.  Repeat the enumeration by using the DownloadString method from the System.Net.WebClient class in order to download PowerView from your Kali system and execute it in memory without saving it to the hard disk. \n']), (
                        '21.2.5.2 Exercises \n', ['21.2.5 \n',
                                                  '1.  Repeat the steps from this section to discover the service principal name for the IIS server. \n',
                                                  '2.  Discover any additional registered service principal names in the domain. \n',
                                                  '3.  Update the script so the result includes the IP address of any servers where a service principal name is registered. \n',
                                                  '4.  Use the Get-SPN script638 and rediscover the same service principal names. \n']), ('21.3.3.1 Exercises \n',
                                                               ['21.3 Active Directory Authentication \n',
                                                                '1.  Use Mimikatz to dump all password hashes from the student VM. \n',
                                                                '2.  Log in to the domain controller as the Jeff_Admin account through Remote Desktop and use Mimikatz to dump all password hashes from the server. \n']), ('21.3.4.1 Exercises \n', ['21.3.4 \n',
                                                                                                       '1.  Repeat the manual effort of requesting the service ticket, exporting it, and cracking it by using the tgsrepcrack.py Python script. \n',
                                                                                                       '2.  Perform the same action with any other SPNs in the domain. \n',
                                                                                                       '3.  Crack the same service ticket using John the Ripper. \n',
                                                                                                       '4.  Use the Invoke-Kerberoast.ps1 script to repeat these exercises. \n']),
                        ('21.3.5.1 Exercises \n', ['21.3.5 \n',
                                                   '1.  Use the PowerShell script in this module to guess the password of the jeff_admin user. \n',
                                                   '2.  Use the Spray-Passwords.ps1 tool to perform a lookup brute force attack of all users in the domain from a password list. \n']), ('21.4.2.1 Exercise \n', [
        '21.4 Active Directory Lateral Movement \n',
        '1.  Execute the overpass the hash attack above and gain an interactive command prompt on the domain controller. Make sure to reboot the Windows 10 client before starting the exercise to clear any cached Kerberos tickets. \n']), ('21.4.3.1 Exercises \n', ['21.4.3 \n',
                                                                                          '1.  Create and inject a silver ticket for the iis_service account. \n',
                                                                                          '2.  How can creating a silver ticket with group membership in the Domain Admins group for a SQL service provide a way to gain arbitrary code execution on the associated server? \n',
                                                                                          '3.  Create a silver ticket for the SQL service account. \n']),
                        ('21.4.4.1 Exercises \n',
                         ['21.4.4 \n', '1.  Repeat the exercise of launching Notepad using Excel and DCOM. \n', '2. Improve the attack by replacing the VBA macro with a reverse shell connecting back to Netcat on your windows student VM. \n',
                          '3.  Set up a pivoting channel from the domain controller to your Kali machine and obtain a reverse shell. \n']), ('21.5.1.1 Exercises \n',
                                                  ['21.5 Active Directory Persistence \n',
                                                   '1.  Repeat the steps shown above to dump the krbtgt password hash and create and use a \n',
                                                   '2.  Why is the password hash for the krbtgt account changed during a functional level upgrade from Windows 2003 to Windows 2008? \n']), ('22.1.3.1 Exercises \n',
                                                                                               ['21.5.2 \n',
                                                                                                '1.  Start the postgresql service and launch msfconsole. \n',
                                                                                                '3.  Review the hosts’ information in the database. \n']),
                        ('22.2.1.1 Exercise \n', ['22.2 Exploit Modules \n',
                                                  '1.  Exploit SyncBreeze using the existing Metasploit module. \n']),
                        ('22.3.3.2 Exercise \n', ['22.3 Metasploit Payloads \n']), ('22.3.7.1 Exercises \n',
                                                                                    ['22.3.4 \n',
                                                                                     '1.  Create a staged and a non-staged Linux binary payload to use on your Kali system. \n',
                                                                                     '2.  Setup a Netcat listener and run the non-staged payload. Does it work? \n',
                                                                                     '3.  Setup a Netcat listener and run the staged payload. Does it work? \n',
                                                                                     '4.  Get a Meterpreter shell on your Windows system. Practice file transfers. \n',
                                                                                     '5.  Inject a payload into plink.exe. Test it on your Windows system. \n',
                                                                                     '6.  Create an executable file running a Meterpreter payload and execute it on your Windows system. \n',
                                                                                     '7.  After establishing a Meterpreter connection, setup a new transport type and change to it. \n']),
                        ('22.4.1.1 Exercise \n', ['22.4 Building Our Own MSF Module \n',
                                                  '1.  Create a new Metasploit module for your SyncBreeze exploit. \n']),
                        ('22.5.4.1 Exercise \n', ['22.5 Post-Exploitation with Metasploit \n',
                                                  '1.  Use post-exploitation modules and extensions along with pivoting techniques to enumerate and compromise the domain controller from a meterpreter shell obtained from your Windows 10 client. \n']),
                        ('22.6.1.1 Exercise \n', ['22.6 Metasploit Automation \n', 'with the meterpreter payload. \n']),
                        ('23.1.3.1 Exercises \n', ['22.7 Wrapping Up \n',
                                                   '1.  Install and start PowerShell Empire on your Kali system. \n',
                                                   '2.  Create a PowerShell Empire listener on your Kali machine and execute a stager on your Windows 10 client. \n',
                                                   '3.  Experiment with the PowerShell Empire agent and its basic functionality. \n']),
                        ('23.3.1.1 Exercises \n', ['23.2 PowerShell Modules \n',
                                                   '1.  Set up a PowerShell Empire listener and stager and obtain a working agent. \n',
                                                   '2.  Perform enumeration on the domain using various modules. \n',
                                                   '3.  Perform a remote desktop login with the account Jeff_Admin to ensure the credentials are cached on the Windows 10 client and then dump the credentials using PowerShell Empire. \n',
                                                   '4.  Experiment with the different lateral movement modules. \n']), (
                        '24.2.2.2 Exercise \n', ['23.4 Wrapping Up \n',
                                                 '1.  Use sqlmap to exploit the SQL injection and extract the username and password. \n']),
                        ('24.5.1.1 Exercises \n',
                         ['24.2.3 \n', '1.  Modify the original Python exploit and capture the reverse shell. \n',
                          '2.  The original UDF exploit is advertised as a privilege escalation exploit. Why are we getting an unprivileged shell? \n'])])

form = cgi.FieldStorage()

print('Content-type: text/html\n')
# Required by tables plugin
print('<link rel="stylesheet" href="../trumbowyg/dist/plugins/table/ui/trumbowyg.table.min.css">')
# Required by highlight plugin
print('<link rel="stylesheet" href="../trumbowyg/dist/plugins/highlight/ui/trumbowyg.highlight.min.css">')
# Required by highlight plugin
print('<link rel="stylesheet" href="../trumbowyg/dist/ui/trumbowyg.min.css">')
# Trumbowyg Core
print("""<script src="http://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
<script>window.jQuery || document.write('<script src="/js/vendor/jquery-3.3.1.min.js"><\/script>')</script>""")
# Required by highlight plugin - also in ../prism-master/components/
# and at https://cdn.jsdelivr.net/npm/prismjs@1.23.0/components/prism-css.min.js"
print('<script src="/static/prism-master/prism.js"></script>')
print('<script src="/static/prism-master/components/prism-asciidoc.min.js"></script>')
print('<script src="/static/prism-master/components/prism-asm6502.min.js"></script>')
print('<script src="/static/prism-master/components/prism-aspnet.min.js"></script>')
print('<script src="/static/prism-master/components/prism-bash.min.js"></script>')
print('<script src="/static/prism-master/components/prism-batch.min.js"></script>')
print('<script src="/static/prism-master/components/prism-c.min.js"></script>')
print('<script src="/static/prism-master/components/prism-cil.min.js"></script>')
print('<script src="/static/prism-master/components/prism-clike.min.js"></script>')
print('<script src="/static/prism-master/components/prism-css.min.js"></script>')
print('<script src="/static/prism-master/components/prism-dns-zone-file.min.js"></script>')
print('<script src="/static/prism-master/components/prism-docker.min.js"></script>')
print('<script src="/static/prism-master/components/prism-git.min.js"></script>')
print('<script src="/static/prism-master/components/prism-go.min.js"></script>')
print('<script src="/static/prism-master/components/prism-http.min.js"></script>')
print('<script src="/static/prism-master/components/prism-json.min.js"></script>')
print('<script src="/static/prism-master/components/prism-java.min.js"></script>')
print('<script src="/static/prism-master/components/prism-javascript.min.js"></script>')
print('<script src="/static/prism-master/components/prism-nginx.min.js"></script>')
print('<script src="/static/prism-master/components/prism-nasm.min.js"></script>')
print('<script src="/static/prism-master/components/prism-perl.min.js"></script>')
# BROKEN PHP print('<script src="/static/prism-master/components/prism-php.min.js"></script>')
print('<script src="/static/prism-master/components/prism-powershell.min.js"></script>')
print('<script src="/static/prism-master/components/prism-python.min.js"></script>')
print('<script src="/static/prism-master/components/prism-shell-session.min.js"></script>')
print('<script src="/static/prism-master/components/prism-sql.min.js"></script>')
print('<script src="/static/prism-master/components/prism-regex.min.js"></script>')
print('<script src="/static/prism-master/components/prism-ruby.min.js"></script>')
# Trumbowyg Core
print('<script src="../trumbowyg/dist/trumbowyg.min.js"></script>')
# Required by highlight plugin, extended languages
print('<script src="/static/prism-master/components/prism-python.min.js"></script>')
# Required by highlight plugin
print('<script src="../trumbowyg/dist/plugins/highlight/trumbowyg.highlight.min.js"></script>')
# Enable Upload
print('<script src="../trumbowyg/dist/plugins/upload/trumbowyg.upload.min.js"></script>')
# Enable Tables
print('<script src="../trumbowyg/dist/plugins/table/trumbowyg.table.min.js"></script>')
# Enable indent/unindent
print('<script src="../trumbowyg/dist/plugins/indent/trumbowyg.indent.min.js"></script>')
# Enable clean paste
print('<script src="../trumbowyg/dist/plugins/cleanpaste/trumbowyg.cleanpaste.min.js"></script>')
# Enable pasting image
print('<script src="../trumbowyg/dist/plugins/pasteimage/trumbowyg.pasteimage.min.js"></script>')
# Enable Base64 images
print('<script src="../trumbowyg/dist/plugins/base64/trumbowyg.base64.min.js"></script>')
# Trumbowyg Core
print('<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.13.0/themes/prism.css">')
print('<TITLE>Problem Set Browser</TITLE>')
print('<H1>Review problem sets, and supply solutions</H1>')
print('<P>In this problem set there are ' + str(len(problems)) + ' exercises.</P>')
print('<P>Within the exercises, there are problems complete.</P>')

html = """
<P>%s</P><BR>"""
# print(problems)

# Return only the list of the exercises
# for key, value in problems.items():
#    print(key, value)

for key, value in problems.items():
    # If we have a "problem" line with a number or two and a dot followed by text, i.e. "2. Lorem ipsum dolor sit amet, consectetur..."
    if re.match(r'\d{1,2}\..*', key):
        if not 'problem' in form:
            # No problem selected, display all problems
            if not 'subsection' in form:
                print("<a href='HTTP://localhost/cgi-bin/psetBrowse.py?problem=" + str(key).split(' ')[0] +
                      "&subsection=" + str(key.split('.')[0]) + "'>" + str(key).split(' ')[0] + "</a><BR>")
        # Otherwise, you must be a problem set
        else:
            if str(key).split(' ')[0] == str(form['problem'].value):
                    print('<H1>' + str(key).strip(' \n') + '</H1><HR>')
                    for j in value:
                        print(j + "<BR><BR>")
                        if re.match(r'^\d{1,2}\.', str.split(j, ' ')[0]) and not re.match(r'^\d{1,2}\.\d{1,2}', str.split(j, ' ')[0]):
                            url = "submit.py?problem=" + str(key).split(' ')[0] + "&question=" + str.split(j, '.')[0]
                            # student submit read
                            # GET submit.py?problem=2.4.3.4&question=1 for read, (student=crypt)
                            # ephemeral storage provides crypt to UUID referencing
                            # UUID from storage is used to call upload.py?file=UUID returning solution contents
                            # try:
                            # submit.py?problem=2.4.3.4&question=1
                            # request from a dictionary the uuid of the contents of a file fooby foo
                            ps = "2.4.3.4:1"
                            f = "2.4.3.4"
                            try:
                                with open('database/' + f, 'r') as j:
                                    a = j.readline()
                                    j.close()
                                    try:
                                        b = ast.literal_eval(a)
                                    except:
                                        b = {ps: ""}
                            except FileNotFoundError:
                                print("<form action='http://localhost/cgi-bin/" + url + " method='post'>")
                                print("<textarea name='content' class='my-editor'></textarea><input type='submit' value = 'Submit'></form>")
                            except EOFError:
                                print("<form action='http://localhost/cgi-bin/" + url + " method='post'>")
                                print("<textarea name='content' class='my-editor'></textarea><input type='submit' value = 'Submit'></form>")
                            else:
                                print("<form action='http://localhost/cgi-bin/" + url + " method='post'>")
                                print("<textarea name='content' class='my-editor'>" + b[ps] + "</textarea><input type='submit' value = 'Submit'></form>")
                            finally:
                                print("""<script type=text/javascript>
$.trumbowyg.svgPath = '../trumbowyg/dist/ui/icons.svg';
$('.my-editor').trumbowyg({
    removeformatPasted: true,
    btns: [
        ['viewHTML'],
        ['undo', 'redo'], // Only supported in Blink browsers
        ['formatting'],
        ['strong', 'em', 'del'],
        ['superscript', 'subscript'],
        ['link'],
        ['upload', 'insertImage', 'base64'],
        ['table'],
        ['justifyLeft', 'justifyCenter', 'justifyRight', 'justifyFull'],
        ['indent', 'outdent'],
        ['unorderedList', 'orderedList'],
        ['horizontalRule'],
        ['removeformat', 'highlight',],
        ['fullscreen']
    ],
    plugins: {
        upload: {
            serverPath: '/cgi-bin/upload.py',
        }
    }
});
</script>""")
