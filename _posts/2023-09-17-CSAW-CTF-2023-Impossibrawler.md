---
title:  "CSAW CTF 2023 - Impossibrawler! [Reversing]"
date:   2023-09-17 00:00:00
categories: [Reversing]
tags: [Reversing]
---
Last week, i participated in CSAW CTF 2023 with the Kernel Escape team and managed to solve several challenges. One of the challenges that I solved was the Impossibrawler! (Reversing).

<!--more-->

**Challenge Description:**\
`How do I beat these guys?!`\
`Author: barrwani`

**Attachment:**\
[Impossibrawler.pck](/files/Impossibrawler.pck)\
[Impossibrawler.exe](/files/Impossibrawler.exe)

**Overview:**
![Overview](/images/post/CSAWCTF2023_overview.png)

I'm trying to see what this game is like first. It's known to be a shooting game where there are enemies and two stages. Our goal in this game is to kill all the enemies. If all the enemies are killed, then it will advance to stage 2, and will get a flag if all the enemies also die in that stage.

**Idea:**\
My idea to solve this is "How can i advance to stage 2 without killing the enemies, and how can i obtain the flag in stage 2 without killing the enemies as well?"

**Tools:**\
[gdsdecomp]("https://github.com/bruvzg/gdsdecomp")\
[Godot Engine Editor](https://godotengine.org/download/windows/)

**Decompiling:**\
What is PCK file extension? a PCK file is a resource pack created by Godot Engine, an open-source game engine used to create 2D and 3D games. [Sources]("https://fileinfo.com/extension/pck")

So, how i can decompile PCK file? Based on this article [here]("https://mahaloz.re/2021/10/03/tasteless-21-tasteless-shores.html"), we can decompile the PCK file for analysis using the decompiler tool named [gdsdecomp]("https://github.com/bruvzg/gdsdecomp").

Okay, lets decompile the PCK file first.

![Decompile](/images/post/CSAWCTF2023_decompile.png)

Steps to Decompile:
1. Open Godot RE Tools ([gdsdecomp]("https://github.com/bruvzg/gdsdecomp"))
2. Click RE Tools Menu
3. Click Recover Project
4. Browse PCK file
5. Choose Full Recovery
6. Set Destination folder
7. Extract

Here is the output after decompiling the PCK file:
![Decompile Output](/images/post/CSAWCTF2023_output_decompile.png)

All the source code are inside the "Scripts" directory:
![Scripts](/images/post/CSAWCTF2023_scripts.png)

Let's move to the [Godot Engine Editor](https://godotengine.org/download/windows/) to analyze the Source Code within the "Scripts" directory.

**Analysis:**\
Here is the initial view using the Godot Engine for debugging and analyzing the source code of the PCK file.
![Initial View](/images/post/CSAWCTF2023_godotengineview.png)

For analysis, i am focusing on the "Level_1.gd" and "Level_2.gd" files in the "Scripts" directory because they are related for obtaining the flag.

After reviewing both files, i am focused on its "if condition".

**Level_1.gd**\
There is a condition that checks if the remaining enemies are equal to "0". If so, it will initiate a seeding process and generate a random number before transitioning to scene 2.\
![Level_1.gd](/images/post/CSAWCTF2023_level1.png)

**Level_2.gd**\
Same as Level_1.gd, there is a condition that checks if the remaining enemies are equal to "0". The different is, this is final stage. Where the enemies left are "0", we will obtain the flag.
![Level_2.gd](/images/post/CSAWCTF2023_level2.png)

**Solver:**\
Since the if condition in both files only checks if the remaining enemies are equal to "0", we can modify it to check for not equal to "0". Therefore, when the game is played, as long as there are remaining enemies greater than "0", it will proceed to stage 2. The same applies to stage 2, and it will immediately display the flag.\
**Level_1.gd modified:**\
![Level_1.gd modify](/images/post/CSAWCTF2023_level1_modify.png)\
**Level_2.gd modified:**\
![Level_2.gd modify](/images/post/CSAWCTF2023_level2_modify.png)\

Save, Play the Project, and We got the Flag!
![Flag](/images/post/CSAWCTF2023_flag.png)

**FLAG: csawctf{302e323032323732}**

Thank you for reading this article, i hope it was helpful :-D\
**Follow me on: [Linkedin], [Medium], [Github], [Youtube], [Instagram]**

[Linkedin]: https://www.linkedin.com/in/muhammad-ichwan-banua/
[Medium]: https://banua.medium.com
[Github]: https://github.com/banuaa
[Youtube]: https://www.youtube.com/@muhammad.iwn-banua
[Instagram]: https://www.instagram.com/muhammad.iwn
