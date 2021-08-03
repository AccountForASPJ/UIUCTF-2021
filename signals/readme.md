## Challenge description
![image](https://user-images.githubusercontent.com/24536991/127945107-0d0a4286-42cd-4b0c-a28a-830ec81eb5cd.png)

Binary provided: signals

Discompiling the binary with ghidra and viewing the main function... 

![image](https://user-images.githubusercontent.com/24536991/127954191-0f1331bf-f388-4833-93df-43ce7cc034b6.png)

The logic in the main function is fairly simple. It accepts the flag as the first argument.
1. It fork out a child process that execute code(), which is the flag verification function.
2. The parent process waits for the child process to end and check if the flag verification result is correct.

So we need to take a look at code()

![image](https://user-images.githubusercontent.com/24536991/127955111-564fd0d6-b419-4074-9f48-59430b2a4799.png)

In order to debug the code(), I have patch the binary so that the parent will execute code() instead of the child process. You can change this assembly instruction from JZ (74 29) to JNZ (75 29) or JMP (EB 29) using Ghidra (or in my case I use hex editor :D)

![image](https://user-images.githubusercontent.com/24536991/127955474-64e903d3-4eea-47b3-a671-13942597ebb4.png)

Running the program and setting breakpoints.....

![image](https://user-images.githubusercontent.com/24536991/127955759-05e81682-9683-4caa-b227-9fa9fc4bd17e.png)

We can see that RCX points to our input. Interestingly, the code loads an address to RAX at the start and JMP RAX at the end, after some XOR of course. So we set a breakpoint at JMP rax and see how the next instruction looks like.

![image](https://user-images.githubusercontent.com/24536991/127956255-fe13bf86-6f86-4ec3-8324-ca775f50fc0c.png)

We got back a batch of instruction that looks almost identical! Only the first instruction is slightly different. Repeating this process get back the same result, that is until your flag is wrong....

In short, this is how the the code works:
1. the first instruction `lea rax, qword[0x5592249ce435]` loads the next instruction to be decoded.
2. bytes[RCX] stores the current character, this is stored in the LSB of RDX in the second instruction
3. 3-7th instruction - xor the current character with the next 0x1d bytes of the address @rax
4. 8th instruction `inc rcx` - next character
5. 9th instruction - `jmp rax` - execute the next batch of instruction
6. Go back to 1

Since we know that the first byte of the next instruction is always 0x48, we can calculate each characters of the flag using (first byte of instruction before the XOR) ^ 0x48.
With this I reimplemented the XOR algorithm in python to print out the flag.

```
from pwn import *
def twos_comp(val, bits):
    """compute the 2's complement of int value val"""
    if (val & (1 << (bits - 1))) != 0: # if sign bit is set e.g., 8bit: 128-255
        val = val - (1 << bits)        # compute negative value
    return val


f = open("signals","rb")
code = bytearray(f.read())
#print(code)
offset= 0x3020 # this is the offset of code() 

flag = b'u'
offset = offset + 7 + u32(code[offset+3:offset+7])
while flag[-1] != ord('}'):
    #print(hex(code[offset]^flag[-1]))
    if  (code[offset] ^ flag[-1]) == 0x48 :
        for i in range(0x1d):
            code[offset+i] = code[offset+i] ^ flag[-1]
        offset = offset + 7 + twos_comp(u32(code[offset+3:offset+7]),32)
        flag = flag + chr(code[offset] ^ 0x48).encode('utf-8')
    else:
        print("error")
        break
print(flag)
```

Flag: uiuctf{another_ctf_another_flag_checker}
