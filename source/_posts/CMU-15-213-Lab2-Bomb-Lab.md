---
title: CMU 15-213 Lab2 Bomb Lab
date: 2022-01-21 02:49:27
tags: 15-213
---

# CMU 15-213 Lab2 Bomb Lab
![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220119222637.png)

<!--more-->

## phase_1

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220119224600.png)

`0x400e32` 要求输入一个字符串并且进入 `phase_1` 函数

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220119224715.png)

`phase_1` 代码，将输入数据与 `0x402400` 地址数据做比较，正确退出函数，错误进入 `explode_bomb`

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220119224932.png)

获取 `0x402400` 处字符串数据

`Border relations with Canada have never been better.`

__phase_1 end__

## phase_2

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220119231123.png)

`read_six_number` 函数，要求输入 6 个数字，依次储存在 `rsi` 指向的地址中

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220119231609.png)

`phase_2` 代码，红色标记处指出，输入第一个数字为 1 ，其后每一个数字为前一个数字的 2 倍

则应该输入的 6 个数字分别为:

`1 2 4 8 16 32`

__phase_2 end__

## phase_3

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220120011857.png)

很明显的 `switch` 结构，`0x402470` 是跳转表的位置，输入对应的 case 数据与比较的数据即可通过

case|judge
---|---:
0| 207
1| 311
2| 707
3| 256
4| 389
5| 206
6| 682
7| 327

## phase_4

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220120022657.png)

`func4` 汇编代码，这里有一个二分的操作 对应的 C 代码应该是

```C
int func4(int a, int b, int c)
{
    int n = (c - b) / 2 + b;
    int result = 0;
    if (n > a)
    {
        return func4(a, b, n - 1) * 2;
    }
    else if (n < a>)
    {
        return func4(a, n + 1, c) * 2 + 1;
    }
    return result;
}

```

最开始时 `b` 为 `0` ，`c` 为 `14`, `n = 7`，
要使每一次递归中返回结果都为 `0` ,则要满足 `a <= n`
且最后 `a` 一定等于 `n`
`n` 的取值有 `7 3 1 0`
及当`a` 为 `7/3/1/0` 时 `func4` 返回 `0`

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220120024229.png)
从 `phase_4` 的代码中，我们可以知道要使 避免 `explode_bomb` 我们可以输入 `7 0 / 3 0 / 1 0 / 0 0 `任意一组输入即可通过

__phase_4 end__

## phase_5

函数 `phase_5` 输入长度为 6 的字符串，将字符串中每一个字符 `& 0xf` 后从字符数组 `maduiersnfotvbyl` 中取出对应 6 个字符，要求结果为 `flyers` 。

计算过程很简单，反汇编代码也很简单，且解并不唯一，这里直接给出一组解为 `IONUVW`

__phase_5 end__

## phase_6

`phase_6` 反汇编代码比较长这里分几个部分，进行分析，写出其伪代码

### part one

```x86asm
00000000004010f4 <phase_6>:
  4010f4:	41 56                	push   %r14
  4010f6:	41 55                	push   %r13
  4010f8:	41 54                	push   %r12
  4010fa:	55                   	push   %rbp
  4010fb:	53                   	push   %rbx
  4010fc:	48 83 ec 50          	sub    $0x50,%rsp
  401100:	49 89 e5             	mov    %rsp,%r13
  401103:	48 89 e6             	mov    %rsp,%rsi
  401106:	e8 51 03 00 00       	callq  40145c <read_six_numbers> ; input 6 numbers to arr[6]
  40110b:	49 89 e6             	mov    %rsp,%r14
  40110e:	41 bc 00 00 00 00    	mov    $0x0,%r12d ; count var i = 0
  401114:	4c 89 ed             	mov    %r13,%rbp
  401117:	41 8b 45 00          	mov    0x0(%r13),%eax ; arr[0]
  40111b:	83 e8 01             	sub    $0x1,%eax
  40111e:	83 f8 05             	cmp    $0x5,%eax
  401121:	76 05                	jbe    401128 <phase_6+0x34> ; arr[0] <= 6
  401123:	e8 12 03 00 00       	callq  40143a <explode_bomb>
  401128:	41 83 c4 01          	add    $0x1,%r12d ; count var i += 1
  40112c:	41 83 fc 06          	cmp    $0x6,%r12d
  401130:	74 21                	je     401153 <phase_6+0x5f> ; i < 6
  401132:	44 89 e3             	mov    %r12d,%ebx ; count var j = i
  401135:	48 63 c3             	movslq %ebx,%rax
  401138:	8b 04 84             	mov    (%rsp,%rax,4),%eax ; arr[j]
  40113b:	39 45 00             	cmp    %eax,0x0(%rbp)
  40113e:	75 05                	jne    401145 <phase_6+0x51>
  401140:	e8 f5 02 00 00       	callq  40143a <explode_bomb>
  401145:	83 c3 01             	add    $0x1,%ebx
  401148:	83 fb 05             	cmp    $0x5,%ebx
  40114b:	7e e8                	jle    401135 <phase_6+0x41>
  40114d:	49 83 c5 04          	add    $0x4,%r13
  401151:	eb c1                	jmp    401114 <phase_6+0x20>
```

对应伪代码如下

```C
    int arr[6];

    scanf("%d %d %d %d %d %d", &arr[0], &arr[1], &arr[2], &arr[3], &arr[4], &arr[5]);

    for (int i = 0; i < 6; ++i)
    {
        if (arr[i] < 1 || arr[i] > 6)
            explode_bomb();
        for (int j = i + 1; j < 6; ++j)
        {
            if (arr[j] == arr[i])
                explode_bomb();
        }
    }
```

这部分代码要求输入6个数字在 1 到 6 之间，且每个数字不重复


### part two

汇编代码如下，这个部分使用到了链表这个结构，和数组指针

下面是 `node` 结构
```x86asm
pwndbg> x/64gx &node1
0x6032d0 <node1>:	0x000000010000014c	0x00000000006032e0
0x6032e0 <node2>:	0x00000002000000a8	0x00000000006032f0
0x6032f0 <node3>:	0x000000030000039c	0x0000000000603300
0x603300 <node4>:	0x00000004000002b3	0x0000000000603310
0x603310 <node5>:	0x00000005000001dd	0x0000000000603320
0x603320 <node6>:	0x00000006000001bb	0x0000000000000000
0x603330:	0x0000000000000000	0x0000000000000000
```

可以发现 `node` 结构是一个链表，前 8 个字节储存,储存他的数据，后 8 个字节储存下一个链表结点的地址

阅读 `0x0000000000401188 <+148>` 地址处代码我们可以知道， `rdx` 中储存的是一个链表接结点的地址，这条汇编语句将这个链表结点数据的地址赋值给了 `[rsp + 0x20]` 开始这个地方的数组，这个数组储存的数据都是指针，所以说这是一个指针数组。

`0x0000000000401153 <+95>` 至 `0x000000000040116d <+121>` 处代码，将 `arr` 数组中每一个被 `7` 减去后，再赋值回去。

`0x0000000000401176 <+130>` 至 `0x0000000000401181 <+141>` 处代码，给根据 `ecx` 中的值，取出链表中对应的第几个结点的地址赋值给 `rdx`寄存器。

`0x000000000040118d <+153>` 至 `0x0000000000401195 <+161>` 处代码是判断循环是否到结尾，即判断 `arr` 数组是否遍历完全

```x86asm
   0x0000000000401153 <+95>:	lea    rsi,[rsp+0x18]
   0x0000000000401158 <+100>:	mov    rax,r14
   0x000000000040115b <+103>:	mov    ecx,0x7
   0x0000000000401160 <+108>:	mov    edx,ecx
   0x0000000000401162 <+110>:	sub    edx,DWORD PTR [rax]
   0x0000000000401164 <+112>:	mov    DWORD PTR [rax],edx
   0x0000000000401166 <+114>:	add    rax,0x4
   0x000000000040116a <+118>:	cmp    rax,rsi
   0x000000000040116d <+121>:	jne    0x401160 <phase_6+108> ; arr[i] = 7 - arr[i]
   0x000000000040116f <+123>:	mov    esi,0x0 ; i = 0
   0x0000000000401174 <+128>:	jmp    0x401197 <phase_6+163>
   0x0000000000401176 <+130>:	mov    rdx,QWORD PTR [rdx+0x8]
   0x000000000040117a <+134>:	add    eax,0x1
   0x000000000040117d <+137>:	cmp    eax,ecx
   0x000000000040117f <+139>:	jne    0x401176 <phase_6+130> ; get number of ecx in nodex
   0x0000000000401181 <+141>:	jmp    0x401188 <phase_6+148>
   0x0000000000401183 <+143>:	mov    edx,0x6032d0 ; node1
   0x0000000000401188 <+148>:	mov    QWORD PTR [rsp+rsi*2+0x20],rdx ; &node.data
   0x000000000040118d <+153>:	add    rsi,0x4
   0x0000000000401191 <+157>:	cmp    rsi,0x18
   0x0000000000401195 <+161>:	je     0x4011ab <phase_6+183>
   0x0000000000401197 <+163>:	mov    ecx,DWORD PTR [rsp+rsi*1]
   0x000000000040119a <+166>:	cmp    ecx,0x1
   0x000000000040119d <+169>:	jle    0x401183 <phase_6+143> ; jmp arr[i] <= 1
   0x000000000040119f <+171>:	mov    eax,0x1
   0x00000000004011a4 <+176>:	mov    edx,0x6032d0
   0x00000000004011a9 <+181>:	jmp    0x401176 <phase_6+130>
```

总结这段代码，就是先将 `arr` 数组每个数被 7 减去再赋值回去，然后根据 `arr` 数组中的值，通过一个链表结构查找对应的第 n 个结点，将其地址赋值给一个数组指针。伪代码形式可以用下面表示


```C
    int *p[6];
    for (int i = 0; i < 6; ++i)
    {
        arr[i] = 7 - arr[i];
    }
    for (int i = 0; i < 6; ++i)
    {
        p[i] = &node(arr[i]).data;
    }
```

### part three

`0x00000000004011ab <+183>` 至 `0x00000000004011d2 <+222>` 处代码将，指针数组 p 指向的链表的结点，重新链接为一个新的链表

`0x00000000004011da <+230>` 至 `0x00000000004011f5 <+257>` 会比较新链表数据部分，前 4 个字节组成的数据，并且要求数据递减

链表前 4 个 bit 数据构成的数字如下

```x86asm
pwndbg> x/32wx &node1
0x6032d0 <node1>:	0x0000014c	0x00000001	0x006032e0	0x00000000
0x6032e0 <node2>:	0x000000a8	0x00000002	0x006032f0	0x00000000
0x6032f0 <node3>:	0x0000039c	0x00000003	0x00603300	0x00000000
0x603300 <node4>:	0x000002b3	0x00000004	0x00603310	0x00000000
0x603310 <node5>:	0x000001dd	0x00000005	0x00603320	0x00000000
0x603320 <node6>:	0x000001bb	0x00000006	0x00000000	0x00000000
```

```x86asm
   0x00000000004011ab <+183>:	mov    rbx,QWORD PTR [rsp+0x20] ; &node1
   0x00000000004011b0 <+188>:	lea    rax,[rsp+0x28] ; get arr p address
   0x00000000004011b5 <+193>:	lea    rsi,[rsp+0x50] ; get end of arr p address
   0x00000000004011ba <+198>:	mov    rcx,rbx ; &node1
   0x00000000004011bd <+201>:	mov    rdx,QWORD PTR [rax] ; p[i]
   0x00000000004011c0 <+204>:	mov    QWORD PTR [rcx+0x8],rdx ; nodex.next = p[i]
   0x00000000004011c4 <+208>:	add    rax,0x8
   0x00000000004011c8 <+212>:	cmp    rax,rsi
   0x00000000004011cb <+215>:	je     0x4011d2 <phase_6+222>
   0x00000000004011cd <+217>:	mov    rcx,rdx
   0x00000000004011d0 <+220>:	jmp    0x4011bd <phase_6+201> ; create new linked list 
   0x00000000004011d2 <+222>:	mov    QWORD PTR [rdx+0x8],0x0
   0x00000000004011da <+230>:	mov    ebp,0x5
   0x00000000004011df <+235>:	mov    rax,QWORD PTR [rbx+0x8]
   0x00000000004011e3 <+239>:	mov    eax,DWORD PTR [rax]
   0x00000000004011e5 <+241>:	cmp    DWORD PTR [rbx],eax
   0x00000000004011e7 <+243>:	jge    0x4011ee <phase_6+250> ; keep decrease
   0x00000000004011e9 <+245>:	call   0x40143a <explode_bomb>
   0x00000000004011ee <+250>:	mov    rbx,QWORD PTR [rbx+0x8]
   0x00000000004011f2 <+254>:	sub    ebp,0x1
   0x00000000004011f5 <+257>:	jne    0x4011df <phase_6+235>
   0x00000000004011f7 <+259>:	add    rsp,0x50
   0x00000000004011fb <+263>:	pop    rbx
   0x00000000004011fc <+264>:	pop    rbp
   0x00000000004011fd <+265>:	pop    r12
   0x00000000004011ff <+267>:	pop    r13
   0x0000000000401201 <+269>:	pop    r14
   0x0000000000401203 <+271>:	ret    

```

到这里我们就开始开发逆向分析，如果要使最后重新链接的新链表的数据部分是递减的，那么新链表的排序应该为 `3 4 5 6 1 2`

这个数字是被 7 减去之后的数字，那么我们原来应该输入的数据就应该为

`4 3 2 1 6 5`

__phase_6 end__

到这里整个炸弹应该就被拆解完成

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220121003027.png)

但是我们在 `phase_defused` 函数中发现了一个 `secret_phase`,继续对他进行分析

## secret_phase

这里先贴一下 `phase_defused` 代码

说一下如何触发 `secret_pahse` 函数，在我们通过 `phase_4` 时 先输入两个数字，再输入 `DrEvil` 字符串，在 `pahse_6` 结束的时候就会触发 `secret_phase` 了

```x86asm
pwndbg> disassemble phase_defused
Dump of assembler code for function phase_defused:
   0x00000000004015c4 <+0>:	sub    rsp,0x78
   0x00000000004015c8 <+4>:	mov    rax,QWORD PTR fs:0x28
   0x00000000004015d1 <+13>:	mov    QWORD PTR [rsp+0x68],rax
   0x00000000004015d6 <+18>:	xor    eax,eax
   0x00000000004015d8 <+20>:	cmp    DWORD PTR [rip+0x202181],0x6        # 0x603760 <num_input_strings>
   0x00000000004015df <+27>:	jne    0x40163f <phase_defused+123>
   0x00000000004015e1 <+29>:	lea    r8,[rsp+0x10]
   0x00000000004015e6 <+34>:	lea    rcx,[rsp+0xc]
   0x00000000004015eb <+39>:	lea    rdx,[rsp+0x8]
   0x00000000004015f0 <+44>:	mov    esi,0x402619
   0x00000000004015f5 <+49>:	mov    edi,0x603870
   0x00000000004015fa <+54>:	call   0x400bf0 <__isoc99_sscanf@plt>
   0x00000000004015ff <+59>:	cmp    eax,0x3
   0x0000000000401602 <+62>:	jne    0x401635 <phase_defused+113>
=> 0x0000000000401604 <+64>:	mov    esi,0x402622 ; "DrEvil"
   0x0000000000401609 <+69>:	lea    rdi,[rsp+0x10]
   0x000000000040160e <+74>:	call   0x401338 <strings_not_equal>
   0x0000000000401613 <+79>:	test   eax,eax
   0x0000000000401615 <+81>:	jne    0x401635 <phase_defused+113>
   0x0000000000401617 <+83>:	mov    edi,0x4024f8
   0x000000000040161c <+88>:	call   0x400b10 <puts@plt>
   0x0000000000401621 <+93>:	mov    edi,0x402520
   0x0000000000401626 <+98>:	call   0x400b10 <puts@plt>
   0x000000000040162b <+103>:	mov    eax,0x0
   0x0000000000401630 <+108>:	call   0x401242 <secret_phase>
   0x0000000000401635 <+113>:	mov    edi,0x402558
   0x000000000040163a <+118>:	call   0x400b10 <puts@plt>
   0x000000000040163f <+123>:	mov    rax,QWORD PTR [rsp+0x68]
   0x0000000000401644 <+128>:	xor    rax,QWORD PTR fs:0x28
   0x000000000040164d <+137>:	je     0x401654 <phase_defused+144>
   0x000000000040164f <+139>:	call   0x400b30 <__stack_chk_fail@plt>
   0x0000000000401654 <+144>:	add    rsp,0x78
   0x0000000000401658 <+148>:	ret    
End of assembler dump.
```

`secret_phase` 和 `func7` 代码

```x86asm
pwndbg> disass secret_phase
Dump of assembler code for function secret_phase:
   0x0000000000401242 <+0>:	push   rbx
   0x0000000000401243 <+1>:	call   0x40149e <read_line>
   0x0000000000401248 <+6>:	mov    edx,0xa
   0x000000000040124d <+11>:	mov    esi,0x0
   0x0000000000401252 <+16>:	mov    rdi,rax
   0x0000000000401255 <+19>:	call   0x400bd0 <strtol@plt>
   0x000000000040125a <+24>:	mov    rbx,rax
   0x000000000040125d <+27>:	lea    eax,[rax-0x1]
   0x0000000000401260 <+30>:	cmp    eax,0x3e8
   0x0000000000401265 <+35>:	jbe    0x40126c <secret_phase+42> ; input > 0 and input <= 1001
   0x0000000000401267 <+37>:	call   0x40143a <explode_bomb>
   0x000000000040126c <+42>:	mov    esi,ebx
   0x000000000040126e <+44>:	mov    edi,0x6030f0
   0x0000000000401273 <+49>:	call   0x401204 <fun7>
   0x0000000000401278 <+54>:	cmp    eax,0x2
   0x000000000040127b <+57>:	je     0x401282 <secret_phase+64>
   0x000000000040127d <+59>:	call   0x40143a <explode_bomb>
   0x0000000000401282 <+64>:	mov    edi,0x402438
   0x0000000000401287 <+69>:	call   0x400b10 <puts@plt>
   0x000000000040128c <+74>:	call   0x4015c4 <phase_defused>
   0x0000000000401291 <+79>:	pop    rbx
   0x0000000000401292 <+80>:	ret    
End of assembler dump.
pwndbg> disass fun7
Dump of assembler code for function fun7:
   0x0000000000401204 <+0>:	sub    rsp,0x8
   0x0000000000401208 <+4>:	test   rdi,rdi
   0x000000000040120b <+7>:	je     0x401238 <fun7+52>
   0x000000000040120d <+9>:	mov    edx,DWORD PTR [rdi]
   0x000000000040120f <+11>:	cmp    edx,esi
   0x0000000000401211 <+13>:	jle    0x401220 <fun7+28>
   0x0000000000401213 <+15>:	mov    rdi,QWORD PTR [rdi+0x8]
   0x0000000000401217 <+19>:	call   0x401204 <fun7>
   0x000000000040121c <+24>:	add    eax,eax
   0x000000000040121e <+26>:	jmp    0x40123d <fun7+57>
   0x0000000000401220 <+28>:	mov    eax,0x0
   0x0000000000401225 <+33>:	cmp    edx,esi
   0x0000000000401227 <+35>:	je     0x40123d <fun7+57>
   0x0000000000401229 <+37>:	mov    rdi,QWORD PTR [rdi+0x10]
   0x000000000040122d <+41>:	call   0x401204 <fun7>
   0x0000000000401232 <+46>:	lea    eax,[rax+rax*1+0x1]
   0x0000000000401236 <+50>:	jmp    0x40123d <fun7+57>
   0x0000000000401238 <+52>:	mov    eax,0xffffffff
   0x000000000040123d <+57>:	add    rsp,0x8
   0x0000000000401241 <+61>:	ret    
End of assembler dump.
```

首先先给出 `fun7` 函数是一个二叉树，输入一个数进入根节点。与根节点进行比较，等于结点值返回 0 。小于结点值则与左结点进行比较，并返回左节点返回值的 2 倍。大于根节点则于右节点进行比较，返回右节点返回值的2倍加 1。

在 `0x0000000000401278 <+54>:	cmp    eax,0x2` 我们可以知道，最终返回的数据是 2 ，所以最后一次返回 0 ，倒数第二次返回 1 ，第三次返回 2，即满足结果。这个结果返回了三次，应当在二叉树的第三层。且第一次进入左子树，第二次向右子树走，结果即为这个点的值。同时这时候我们可以发现，如果接着往下，向左节点走，并且等于左节点的值，那么返回值就一直为 0 。 此时这个结点的返回值为 `2 * 0 + 1 = 1` 结果保证不变。观察下面的图就能得到，能通过该 `secret_phase` 的值有两个分别为 `22(0x16)` `22(0x14)`。

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220121015950.png)


**参考资料：**

http://csapp.cs.cmu.edu/3e/labs.html
https://www.viseator.com/2017/06/21/CS_APP_BombLab/

<center>
    <img src="https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220121022613.png">
</center>

