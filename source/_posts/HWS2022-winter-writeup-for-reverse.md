---
title: HWS2022 winter writeup for reverse
date: 2022-01-25 01:22:04
tags: 
- CTF
- Reverse
---

# HWS2022 winter writeup

HWS2022 硬件冬令营逆向部分 writeup
逆向部分全是 vm 题目，做起来很肝，当然也学到了很多

<!-- more -->


## 1. Reverse

### 1.1. EasyVM

```Python
import base64
arr = [0, 190, 54, 172, 39, 153, 79, 222, 68, 238, 95, 218, 11, 181, 23, 184, 104, 194, 78, 156, 74, 225, 67, 240, 34, 138, 59, 136, 91, 229, 84, 255, 104, 213, 103, 212, 6, 173, 11, 216, 80, 249, 88, 224, 111, 197, 74, 253, 47, 132, 54, 133, 82, 251, 115, 215, 13, 227, 0]

s = ""
for i in range(1, len(arr)):
    # print(chr(arr[i] ^ 0xee ^ arr[i - 1]), end = "")
    s += chr(arr[i] ^ 0xee ^ arr[i - 1])
print(len(s))
t_s = ""
for i in range(0, len(s) - 2, 4):
    t_s += chr(ord(s[i]) ^ 0xa)
    t_s += chr(ord(s[i + 1]) ^ 0xb)
    t_s += chr(ord(s[i + 2]) ^ 0xc)
    t_s += chr(ord(s[i + 3]) ^ 0xd)
# print(t_s)
print(base64.b64decode(t_s))
# b'flag{2586dc76-98d5-44e2-ad58-d06e6559d82a}'
```

### 1.2. BabyVM

存在很多花指令，根据花指令特征先编写脚本去除花指令
```Python
import ida_bytes
ea = 0x41304d
start = 0x412cc0
end = 0x413991
for addr in range(start, end):
    con = ida_bytes.get_bytes(addr,5)
    if con == b'\x74\x03\x75\x01\xe8':
        con = b'\xEB\x03\x90\x90\x90'
        ida_bytes.patch_bytes(addr, con)
```

虚拟机的指令是以一个结构体形式储存，结构体形式如下

```C
struct frame
{
  unsigned __int64 opcode;
  unsigned __int64 arg_1;
  unsigned __int64 arg_2;
};

```

`0x7DE000` 至 `0x7DF158` 部分是储存指令的内存区域，在这个地方创建结构体数组，可以使我们更加清晰的分析虚拟机指令的组成

通过动态调试我们可以知道 `0x7DE000` 到 `0x7DEA50` 部分的 opcode 是用来输出提示信息，以及输入，对我们输入部分进行储存的指令

`0x7DEA68` 至 `0x7DF4E8` 指令部分，是进行输入加密和 check 以及结果输出的指令部分，这里我们先利用 IDAPython 提取出对应的指令序列 然后根据逆向出来的指令操作，打印出这部分指令的伪代码 ，打印脚本如下

```Python
con = [[6, 0, 18446744073709551615], [26, 0, 125], [28, 18, 18446744073709551615], [1, 0, 119], [1, 1, 114], [1, 2, 111], [1, 3, 110], [1, 6, 103], [1, 7, 33], [24, 0, 18446744073709551615], [24, 1, 18446744073709551615], [24, 2, 18446744073709551615], [24, 3, 18446744073709551615], [24, 6, 18446744073709551615], [24, 7, 18446744073709551615], [1, 0, 10], [24, 0, 18446744073709551615], [25, 18446744073709551615, 18446744073709551615], [1, 8, 256], [26, 8, 225], [30, 25, 18446744073709551615], [6, 0, 18446744073709551615], [4, 8, 0], [9, 8, 1], [29, 19, 18446744073709551615], [6, 0, 18446744073709551615], [26, 0, 123], [31, 3, 18446744073709551615], [6, 0, 18446744073709551615], [26, 0, 103], [31, 3, 18446744073709551615], [6, 0, 18446744073709551615], [26, 0, 97], [31, 3, 18446744073709551615], [6, 0, 18446744073709551615], [26, 0, 108], [31, 3, 18446744073709551615], [6, 0, 18446744073709551615], [26, 0, 102], [31, 3, 18446744073709551615], [18, 9, 9], [1, 10, 225], [3, 7, 9], [3, 6, 10], [17, 6, 66], [13, 6, 2], [27, 6, 7], [31, 3, 18446744073709551615], [7, 9, 1], [7, 10, 1], [26, 9, 32], [30, 42, 18446744073709551615], [1, 0, 99], [1, 1, 111], [1, 2, 114], [1, 3, 114], [1, 6, 101], [1, 7, 99], [24, 0, 18446744073709551615], [24, 1, 18446744073709551615], [24, 2, 18446744073709551615], [24, 3, 18446744073709551615], [24, 6, 18446744073709551615], [24, 7, 18446744073709551615], [1, 0, 116], [1, 1, 108], [1, 2, 121], [1, 3, 33], [1, 6, 10], [24, 0, 18446744073709551615], [24, 1, 18446744073709551615], [24, 2, 18446744073709551615], [24, 3, 18446744073709551615], [24, 6, 18446744073709551615], [25, 18446744073709551615, 18446744073709551615]]
arr = [0] * 32
for i in con:
    print(i)
    t = i[0]
    arr[t] = 1

print(arr)
for i in range(0, len(arr)):
    if arr[i] == 1:
        print(i)

for i in range(0, len(con)):
    tmp = con[i]
    arg_1 = tmp[1]
    arg_2 = tmp[2]
    print(f"__{i} : ", end = "")
    if tmp[0] == 1:
        print(f"arr[{arg_1}] = {arg_2}")
    if tmp[0] == 3:
        print(f"arr[{arg_1}] = 7DF[arr[{arg_2}]]")
    if tmp[0] == 4:
        print(f"7DF[arr[{arg_1}]] = arr[{arg_2}]")
    if tmp[0] == 6:
        print(f"arr[{arg_1}] = memory[arr[4]] --- arr[4]--")
    if tmp[0] == 7:
        print(f"arr[{arg_1}] += {arg_2}")
    if tmp[0] == 9:
        print(f"arr[{arg_1}] = arr[{arg_1}] - {arg_2}")
    if tmp[0] == 13:
        print(f"arr[{arg_1}] = arr[{arg_1}] << {arg_2}")
    if tmp[0] == 17:
        print(f"arr[{arg_1}] = arr[{arg_1}] ^ {arg_2}")
    if tmp[0] == 18:
        print(f"arr[{arg_1}] ^ arr[{arg_2}]")
    if tmp[0] == 24:
        print(f"put(arr[{arg_1}])")
    if tmp[0] == 25:
        print(f"exit")
    if tmp[0] == 26:
        print(f"mark_p = arr[{arg_1}] == {arg_2} --- *(mark_p + 1) = arr[{arg_1}] < {arg_2}")
    if tmp[0] == 27:
        print(f"mark_p = arr[{arg_1}] == arr[{arg_2}] --- *(mark_p + 1) = arr[{arg_1}] < arr[arg_2]")
    if tmp[0] == 28:
        print(f"mark_p == 1 --- jmp {arg_1}")
    if tmp[0] == 29:
        print(f"jmp {arg_1}")
    if tmp[0] == 30:
        print(f"*(mark_p + 1) == 1 --- jmp {arg_1}")
    if tmp[0] == 31:
        print(f"mark_p == 0 jmp {arg_1}")
```

指令的伪代码如下

```text
__0 : arr[0] = memory[arr[4]] --- arr[4]--
__1 : mark_p = arr[0] == 125 --- *(mark_p + 1) = arr[0] < 125
__2 : mark_p == 1 --- jmp 18
__3 : arr[0] = 119
__4 : arr[1] = 114
__5 : arr[2] = 111
__6 : arr[3] = 110
__7 : arr[6] = 103
__8 : arr[7] = 33
__9 : put(arr[0])
__10 : put(arr[1])
__11 : put(arr[2])
__12 : put(arr[3])
__13 : put(arr[6])
__14 : put(arr[7])
__15 : arr[0] = 10
__16 : put(arr[0])
__17 : exit
__18 : arr[8] = 256
__19 : mark_p = arr[8] == 225 --- *(mark_p + 1) = arr[8] < 225
__20 : *(mark_p + 1) == 1 --- jmp 25
__21 : arr[0] = memory[arr[4]] --- arr[4]--
__22 : 7DF[arr[8]] = arr[0]
__23 : arr[8] = arr[8] - 1
__24 : jmp 19
__25 : arr[0] = memory[arr[4]] --- arr[4]--
__26 : mark_p = arr[0] == 123 --- *(mark_p + 1) = arr[0] < 123
__27 : mark_p == 0 jmp 3
__28 : arr[0] = memory[arr[4]] --- arr[4]--
__29 : mark_p = arr[0] == 103 --- *(mark_p + 1) = arr[0] < 103
__30 : mark_p == 0 jmp 3
__31 : arr[0] = memory[arr[4]] --- arr[4]--
__32 : mark_p = arr[0] == 97 --- *(mark_p + 1) = arr[0] < 97
__33 : mark_p == 0 jmp 3
__34 : arr[0] = memory[arr[4]] --- arr[4]--
__35 : mark_p = arr[0] == 108 --- *(mark_p + 1) = arr[0] < 108
__36 : mark_p == 0 jmp 3
__37 : arr[0] = memory[arr[4]] --- arr[4]--
__38 : mark_p = arr[0] == 102 --- *(mark_p + 1) = arr[0] < 102
__39 : mark_p == 0 jmp 3
__40 : arr[9] ^ arr[9]
__41 : arr[10] = 225
__42 : arr[7] = 7DF[arr[9]]
__43 : arr[6] = 7DF[arr[10]]
__44 : arr[6] = arr[6] ^ 66
__45 : arr[6] = arr[6] << 2
__46 : mark_p = arr[6] == arr[7] --- *(mark_p + 1) = arr[6] < arr[arg_2]
__47 : mark_p == 0 jmp 3
__48 : arr[9] += 1
__49 : arr[10] += 1
__50 : mark_p = arr[9] == 32 --- *(mark_p + 1) = arr[9] < 32
__51 : *(mark_p + 1) == 1 --- jmp 42
__52 : arr[0] = 99
__53 : arr[1] = 111
__54 : arr[2] = 114
__55 : arr[3] = 114
__56 : arr[6] = 101
__57 : arr[7] = 99
__58 : put(arr[0])
__59 : put(arr[1])
__60 : put(arr[2])
__61 : put(arr[3])
__62 : put(arr[6])
__63 : put(arr[7])
__64 : arr[0] = 116
__65 : arr[1] = 108
__66 : arr[2] = 121
__67 : arr[3] = 33
__68 : arr[6] = 10
__69 : put(arr[0])
__70 : put(arr[1])
__71 : put(arr[2])
__72 : put(arr[3])
__73 : put(arr[6])
__74 : exit

```

通过分析这些伪代码指令 和动态调试，知道了就只是做了一个异或 66 再左移 2 位的操作，从内存中提取出加密后的指令序列，编写代码

```Python
arr = [156, 448, 472, 468, 468, 488, 456, 152, 456, 448, 492, 140, 468, 140, 492, 492, 448, 448, 472, 468, 156, 464, 464, 464, 468, 488, 464, 492, 456, 456, 488, 140]
for i in arr:
    print(chr((i >> 2) ^ 66), end = "")
# e247780d029a7a992247e6667869008a
```

### 1.3. babyre

LLVM 还有控制流平坦化，先尝试网上通用的 deflat 脚本，发现会报错，似乎是有一些 汇编指令 angr 没有办法去模拟

这可就很难受了

(~~呜呜呜~~)

观察代码块后，发现程序中还是由一些花指令，先去除花指令再说 然后就只能手动去分析流程图中的真实块

然后对每一个真实块用注释的形式去给他一个编号，通过动态调试以及静态分析的方法去弄清除每一个真实块的代码行为

将所有的真实块编号标记好之后我们可以将每一个真实块看作 一行代码 (~~伪汇编代码~~)

列出程序逻辑如下

```
__step 0: input_func
__step 1: len(input) != 32  ---> exit
__step 2: key_1 = 0 --- key_2 = 0 --- key_3 = 15 copy_input = input # 将 input 内容复制遍
__step 3: key_1 >= 8 ---> goto step_6
__step 4: key_2 = copy_input[key_1] ^ key_2 --- key_3 = ~copy_input[key_1]
__step 5: ++key_1 --- goto step_3

__step 6: var_1 = 0
__step 7: var_1 >= 8 ---> goto step_10
__step 8: copy_input[var_1] = copy_input[var_1] ^ key_2 --- key_3 = var_1
__step 9: ++var_1 --- goto step_7

__step 10: mark_var = 0 --- var_2 = 0
__step 11: var_2 >= 32 goto step_14
__step 12: mark_var = (char)(copy_input[var_2]) ^ mark_var
__step 13: ++var_2 goto step_11

__step 14: new_mem = (const char *)malloc(0x2Du);
__step 15: *((_BYTE *)new_mem + 44) = 0; --- key_3 = 15 --- var_3 = 0 --- var_4 = 0
__step 16: var_4 >= 33 goto step_23
__step 17: new_mem[var_3:var_3 + 4] = base64(var_4:var_4 + 3) --- var_3 += 4 --- v21 = var_4 + 3
__step 18: v21 > 0x21 goto step_21

(((((((((((((((((( index ))))))))))))))))))
__step 19: copy_input[v21] ^= new_mem[var_3] --- copy_input[v21 + 1] ^= new_mem[var_3 + 1] --- copy_input[v22 + 2] ^= new_mem[var_3 + 2]

__step 20: v21 += 3 goto step_18
__step 21: goto 22
__step 22: var_4 += 3 goto step_16
__step 23: check function
__step 24:
```

其中`step_19` 异或的不是他们 `base` 加密后的值 而是他们的下标

程序流程分析出来，先编写一遍对应的加密代码，根据加密代码再逆向整个过程

加密代码如下

```Python
import libnum
import copy

table = "QVEJAfHmUYjBac+u8Ph5n9Od16FrICL/X0GvtM4qk7T2z3wNSsyoebilxWKgZpRD"
input = b"abcdefghijklmnopqrstuvwxyz123456"
copy_input = copy.copy(input)

key_2 = 0
key_3 = 15
for i in range(0, 32, 4):
    key_2 = libnum.s2n(copy_input[i:i+4][::-1]) ^ key_2
    key_3 = ~libnum.s2n(copy_input[i:i+4][::-1])

tmp = b""
for i in range(0, 32, 4):
    tmp += libnum.n2s(libnum.s2n(copy_input[i:i+4][::-1]) ^ key_2)[::-1]
    key_3 = i // 4

mark_var = 0
for i in range(0 ,32):
    mark_var = libnum.s2n(tmp[i:i +1]) ^ mark_var

var_3 = 0
tmp += b'\x00' * 4
temp = [0] * 60
for i in range(0, len(tmp)):
    temp[i] = ord(tmp[i:i+1])

temp = [107, 101, 96, 102, 104, 53, 97, 53, 110, 48, 97, 49, 57, 96, 61, 99, 53, 101, 102, 50, 108, 48, 99, 48, 107, 96, 96, 48, 107, 51, 61, 96, 93]
temp += [0] * 34
base64ed = [0] * 60
for i in range(0, 32, 3):
    c1 = temp[i]
    c2 = temp[i + 1]
    c3 = temp[i + 2]
    a1 = c1 >> 2
    a2 = ((c1 & 0x3) << 4) + (c2 >> 4)
    a3 = ((c2 & 0xf) << 2) + (c3 >> 6)
    a4 = (c3 &0x3f)
    base64ed[var_3] = ord(table[a1])
    base64ed[var_3 + 1] = ord(table[a2])
    base64ed[var_3 + 2] = ord(table[a3])
    base64ed[var_3 + 3] = ord(table[a4])
    for j in range(i + 3, 32, 3):
        temp[j] ^= a1
        temp[j + 1] ^= a2
        temp[j + 2] ^= a3
    print(temp[0:32])
    var_3 += 4
print(base64ed[0:44])
for i in base64ed:
    print(chr(i), end = "")
# Fi9X/fxX6Q6JBfUfBM1V/y6V6PcPjMaQLl9IuttFuH68
```

根据加密代码 再编写解题代码，即可得到 `flag`


```python
import libnum
s = "Fi9X/fxX6Q6JBfUfBM1V/y6V6PcPjMaQLl9IuttFuH68"
# s = "Fi9X"
t = "QVEJAfHmUYjBac+u8Ph5n9Od16FrICL/X0GvtM4qk7T2z3wNSsyoebilxWKgZpRD"
enc = []
table = []
for i in s:
    enc.append(ord(i))

for i in t:
    table.append(ord(i))


xor_table = []
temp = []
for i in range(0,len(enc), 4):
    a1 = table.index(enc[i])
    a2 = table.index(enc[i + 1])
    a3 = table.index(enc[i + 2])
    a4 = table.index(enc[i + 3])
    c1 = (a1 << 2) + (a2>> 4)
    c2 = ((a2 & 0b1111) << 4) + (a3 >> 2)
    c3 = ((a3 & 0b11) << 6) + a4
    for j in range(0, len(xor_table), 3):
        c1 ^= xor_table[j]
        c2 ^= xor_table[j + 1]
        c3 ^= xor_table[j + 2]
    xor_table.append(a1)
    xor_table.append(a2)
    xor_table.append(a3)
    temp.append(c1)
    temp.append(c2)
    temp.append(c3)
# print(temp)

res = ""
for i in temp:
    res += chr(i)
# print(res)

arr = []
for i in range(0, len(res), 4):
    arr.append(libnum.s2n(res[i:i+4][::-1]))

k = 0
for i in range(0 ,8):
    k ^= arr[i]

for i in range(0 ,8):
    print(str(libnum.n2s(arr[i] ^ k)[::-1], 'utf-8'), end = "")

# fce5e3dfc6db4f808ccaa6fcffecf583
```


## 2. Misc
搜到这两篇文章

Higaisa APT最新LNK攻击
https://www.freebuf.com/articles/network/241414.html

使用Winrm.vbs绕过应用白名单执行任意未签名代码的分析
https://www.freebuf.com/articles/system/178339.html

根据文章中说的方法提取出 xls 脚本 如下

```xsl
<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
 <ms:script implements-prefix="user" language="VBScript">
 <![CDATA[
 rBOH7OLTCVxzkH=HrtvBsRh3gNUbe("676d60667a64333665326564333665326564333665326536653265643336656564333665327c"):execute(rBOH7OLTCVxzkH):function HrtvBsRh3gNUbe(bhhz6HalbOkrki):for rBOH7OLTCVxzkH=1 to len(bhhz6HalbOkrki)step 2:HrtvBsRh3gNUbe=HrtvBsRh3gNUbe&chr(asc(chr("&h"&mid(bhhz6HalbOkrki,rBOH7OLTCVxzkH,2)))xor 1):next:end function:
 ]]> </ms:script>
</stylesheet>

```

将得到的 `676d60667a64333665326564333665326564333665326536653265643336656564333665327c` 每两个字符切割为一个 16 进制数据，然后再异或 1 输出，即可得到结果

脚本
```Python
arr = [0x67, 0x6d, 0x60, 0x66, 0x7a, 0x64, 0x33, 0x36, 0x65, 0x32, 0x65, 0x64, 0x33, 0x36, 0x65, 0x32, 0x65, 0x64, 0x33, 0x36, 0x65, 0x32, 0x65, 0x36, 0x65, 0x32, 0x65, 0x64, 0x33, 0x36, 0x65, 0x65, 0x64, 0x33, 0x36, 0x65, 0x32, 0x7c]
for i in arr:
    print(chr(i ^ 1), end = "")
# flag{e27d3de27d3de27d3d7d3de27dde27d3}
```
