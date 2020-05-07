---
layout: post
title:  "Decompiling Stack Strings in Ghidra"
date:   2020-05-03 15:30:10 -0500
categories: jekyll update
---

In this post, I'll be discussing a method I recently implemented to have stack strings show up in Ghidra's decompiler window. The final script transforms this garbage:

![orig_ss_example](/images/original_ss_example.png)

into this, significatly better garbage:

![new_ss_example](/images/processed_ss_example.png)

so let's get into it.

## Background

If you've seen my [Medium](https://medium.com/@lerner98), you know that I like looking at the Spotify binary. I continued this trend recently since I had a problem with my [Skiptracing](https://medium.com/@lerner98/skiptracing-reversing-spotify-app-3a6df367287d) project. Every so often, I would notice that I wasn't getting new skips recorded from the MacOS client. I ran `otool -L` and my skip tracing dylib was nowhere to be found!

After some investigation, I came to the conclusion that Spotify must be updating itself in the background and overwriting the binary. This was supported by the fact that I had an IDA database in `/Applications/Spotify.app/Contents/MacOS` that disappeared when the skips stopped as well. Spotify is probably just wiping this whole directory.

Anyways, I began to investigate functions that referenced interesting, updated-related strings and to my *horror*, I saw the aforereferenced stack strings. (As an aside, this technically isn't a *stack* string since the pointer is allocated using `new` but I'll just be calling them stack strings since it's easier).

What is this boost/C++ bullshit? I actually don't know a good reason why this would show up in non-malware. Seriously, if anyone knows, email or tweet me.

Hopefully I'll write a blog post on the update process soon but for now, I couldn't live with myself if I let this live in the decompiler. Let's squash this.

## Identifying the Problem

Let's take a look at the assembly that generated our garbage stack string:

![orig_ss_asm](/images/original_ss_assembly.png)

This is made a little harder to read by way of galaxy-brained Ghidra renaming registers so let's go through it step by step.

#### Allocate the string

```assembly
mov edi, 0x30                       ; allocate 0x30 bytes
call operator.new
mov qword port [rbp - 0xf0], rax    ; store the pointer to the buffer at rbp - 0xf0
```

#### Some C++ bullshit

The next two instructions move two quadwords onto the stack just before our buffer pointer. I assume this has to deal with some sort of class member initialization for `std::string` but I'm not sure. I really, really hate C++ reverse engineering. Again, if anyone knows, let me know.

#### Create the string

```assembly
mov rcx, <packed chars>
mov qword ptr [rax + offset], rcx
```

This repeats several times until we finally write the null terminator:

```assembly
mov byte ptr [rax + offset], 0x0
```

Now, we could write some instruction regex's and that would be all good and well, but looking at other stack strings in the function, there are some peculiarities that make this difficult.

For example, some of the stack strings are actually stack strings, that is they're built on the stack:

![actual_ss](/images/actual_ss_example.png)

Therefore, we'll want to be handle to handle multiple pointer registers. In addition, in the above example, "RL." is moved as a double word, including the null-terminator, so we can't assume that a part of the string is all printable ASCII.

Now all this could probably be done with some complicated regexs, but who likes writing regexs? Let's have some fun with everyone's favorite IL, pcode! (Another advantage of using pcode is that the stack string detection bit is architecture-independent!)

## A Gentle Introduction to Pcode

Pcode, Ghidra's IL, is a register transfer language. This means that operations like load, store, add, etc. all take their inputs/send their outputs to "registers". I say "registers" in quotes because they aren't aren't just the architecture's registers like RAX and RDI, but an abstraction for all of the machine's memory.

Since it's still important to know whether or not data is in a machine register or ram, each pcode memory location, known as a varnode, has an associated address space. This address space represents where the memory is located, like `ram` for ram, `register` for a machine register, or `const` for an immediate value among others.

Take a look at the [official Ghidra docs](https://ghidra.re/courses/languages/html/pcoderef.html) for a better explanation.

Now that we kind of know what pcode is, let's look at the pcode for our stack string building instructions:

![pcode_example](/images/copy_store_pcode_example.png)

Let's deconstruct the two instructions pictured.

#### mov rax, "Invalid "

This instruction is translated into a single pcode COPY operation. COPY, as you might expect, copies the memory specified by the varnode on the rhs into the varnode on the lhs.

We now get a good look at how a varnode is represented. For example, the destination for the COPY, rax, is represented as:

    (register, 0x0, 8)

This illustrates how each varnode basically a 3-tuple composed of an `(address space, offset, size)`. For rax, it is a machine register, so it goes into the `register` space, it is the first register in Ghidra's processor definition (this is arbitrary) so it's offset is 0, and rax is a 64-bit register, so the size of the varnode is 8 bytes.

Looking on the rhs, we can see that our packed chars are represented as:

    (const, <big long hex string>, 8)

The peculiar thing to note is the offset for this varnode. For constant varnodes, the offset is the immediate value. I feel like overloading the offset field makes some operations more difficult to understand but what do I know.

#### mov qword ptr [rbp - 0xff], rax

We see that this instruction is actually translated into three pcode operations: an INT_ADD, a COPY, and a STORE. Let's go over each operation.

First we have `(unique, 0x640, 8) = INT_ADD (register, 0x28, 8), (const, -0xff, 8)`. The INT_ADD operation, as one would expect, adds the two operands. The first operand is a register with offset 0x28, which corresponds to rbp and the second operand is a constant like we saw before.

The output is somethning we haven't seen before, a varnode in the `unique` address space. The `unique` space is sort of a scratch space where temporary values (like an offseted-register) are stored.

The next operation is a COPY. This should look familiar. The only difference between this COPY and the previous one is that the source is a register instead of a constant.

Finally, there's a STORE operation. The second and third inputs are pretty intuitive: the second input is the destination and the third input is the data to store. In this case, the destination is at offset 0x640 in the `unique` space. Looking at the first operation, this is where `rbp - 0xff` was stored. The data is taken from `unique` 0x1ff0, where rax was copied into.

The unintuitive parameter is the first one. This is the space ID of the destination varnode. To be honest, I'm not 100% sure as to why the space of the destination varnode isn't this value, but that's just the way it is. I think it might be an ID for the memory block in Ghidra (i.e. `ram`) but I feel like I've seen mixed results confirming this. Regardless, we don't care about it. Get it out of here!

## Detecting Stack Strings with Pcode

We'll now work on writing the code to detect this pattern in pcode. This section will get pretty far into the weeds so skip it if you don't want to know the ins and outs of emulating pcode. The tl;dr is to detect COPY's followed by STORE's but the implementation's tedious.

<details>
<summary>The <i>Code</i></summary>

We'll start by processing the instructions in the current function:

```python
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.pcode import PcodeOp

ca = currentAddress
cp = currentProgram
fp = FlatProgramAPI(cp)

fn = fp.getFunctionContaining(ca)
cont_fn = fn

entry = fn.getEntryPoint()
insn = fp.getInstructionAt(entry)

while insn is not None and fn == cont_fn:
    for pc in insn.pcode:
        # Emulate each pcode operation
        output_varnode = pc.output
        value = get_pcode_value(pc)

        if output_varnode is not None and value is not None:
            set_varnode_value(output, value)

        # Handle the ops specific to stack string creation
        if pc.opcode == PcodeOp.COPY:
            handle_copy(pc)
        elif pc.opcode == STORE:
            handle_store(pc)

    insn = insn.next
    if insn is not None:
        cont_fn = fp.getFunctionContaining(insn.address)
```

This is just boilerplate to get all of the pcode (there are other ways through the decompiler but you'll get different pcode). It gives a good look at the Ghidra pcode API which is for the most part intuitive (we'll see the unintuitive parts later).

First, let's go through the pcode-emulating functions `get_pcode_value` and `set_varnode_value`.

```python
BINARY_PCODE_OPS = { 
    PcodeOp.INT_ADD: '+',
    PcodeOp.PTRSUB: '+', 
    PcodeOp.INT_SUB: '-',
    PcodeOp.INT_MULT: '*'
}

def get_pcode_value(pcode):
    if pcode is None:
        return None

    opcode = pcode.getOpcode()

    if opcode in BINARY_OPS:
        op1 = get_varnode_value(pcode.getInput(0))
        op2 = get_varnode_value(pcode.getInput(1))

        if op1 is None or op2 is None:
            return None

        oper = BINARY_OPS[opcode]

        # get_varnode_value can return an integer or a string
        if type(op1) == str or type(op2) == str:
            op1 = str(op1)
            op2 = str(op2)
            return '%s%s%s' % (op1, oper, op2)
        else:
            return eval('%d %s %d' % (op1, oper, op2)
    ...
    elif opcode == PcodeOp.COPY:
        return get_varnode_value(pcode.getInput(0))
    ...
```

This function is just a big switch statement handling as many pcode operations as I was patient to handle. The only thing to note is that `get_varnode_value` can return a function or a string. This is because when trying to get the value of a varnode in the `register` space, we'll just return the register name. Not great but it works for now.

Speaking of `get_varnode_value`, let's take a look:

```python
from ghidra.program.model.pcode import VarnodeTranslator

name2space = {
    'register': {},
    'unique': {}
}

def get_varnode_value(varnode):
    space_name = varnode.getAddress().addressSpace.name
    offset = varnode.offset
    addr = fp.toAddr(offset)

    if space_name == 'const':
        return offset

    elif space_name == 'ram' and is_address_in_current_program(addr):
        return get_value_from_addr(addr, varnode.size)

    if space_name in name2space and offset in name2space[space_name]:
        return name2space[space_name][offset]

    if space_name == 'register':
        translator = VarnodeTranslator(cp)
        reg = translator.getRegister(varnode)

        if reg is not None:
            return str(reg.name)

    return None
```

Note that there are some helper functions like `get_value_from_addr` that I left out for brevity but should hopefully be pretty self-explanatory as to what they do.

Similar to `get_pcode_value`, this function is a switch statement on the possible varnode address spaces. Here's a rundown of how I handle all the different spaces:

1. `const`: Return the varnode's offset.
2. `ram`: Return the bytes from the file corresponding to the specified address.
3. `unique`: If we previously tracked a write to the varnode's offset in the `unique` space, return it.
4. `register`: Return any previously tracked register writes. If no such writes exist, return the register name as a string.

Now all we need for pcode emulation is the ability to set a varnode's value on a write:

```python
def set_varnode_value(varnode, value):
    space_name = varnode.getAddress().addressSpace.name
    if space_name not in name2space:
        return

    name2space[space_name][varnode.offset] = value

def clear_varnodes():
    for space_name in name2space.keys():
        name2space[space_name] = {}
```

I've defined another function `clear_varnodes` to remove any varnode's we've previously tracked. This is because registers and varnodes in the `unique` space are often reused so we'll want to clear any stale values (especially for registers) once we're done moving a stack string.

Let's now go over our functions to handle COPY and STORE pcode operations.

#### Handling COPY

For COPY, the basic approach we'll take is: detect constant varnodes with a lot of ASCII characters. Simple, right?

```python
import binascii
import string

# A flag for whether or not we are in the middle of constructing a stack string
found_ss = False

# Placeholders for the register and offset that a stack string is moved into
ss_reg, ss_off = None, 0,

# Placeholder for the stack string itself
ss = ''

# A list of blocks of contiguous instructions that were used to create our stack string
ss_insns = []

# A mapping from a stack string to its register, offset, etc.
stack_strings = {}

def handle_copy(pc):
    inpt = pc.getInput(0)
```

First, we'll check to make sure that we're copying at least four bytes from to `const` space. If we are in the middle of constructing a stack string, decrease that lower bound to two since we might only be moving a small portion of the string:

```python
    min_num_bytes = 4
    if found_ss:
        min_num_bytes = 2
    
    if inpt.size < min_num_bytes or inpt.getAddress().addressSpace.name != 'const':
        return
```

Then we'll convert the offset into bytes and check if it's at least 50% ascii. You'll notice that I'm using binascii even though there are better ways. This is because `bytes` in Python2 are weird so after a lot of wrestling, I just gave up and used a kind of weird method that just worked:

```python
    offset = inpt.offset

    # We need an even number of bytes to decode with binascii
    if len(hex(offset)) % 2 == 0:
        return

    # Convert it to bytes
    bs = binascii.unhexlify(hex(offset)[2:-1])[::-1]

    # Check that at least 50% of it is printable
    nprintable = len([b for b in bs if b in string.printable])
    if nprintable / float(len(bs)) < 0.5:
        return
```

Next, we're going to have to see if we should add a null-terminator(s) to the string. If you refer to one of the previous examples, the string "RL." was moved as a dword even though it's only three characters. Therefore, if our string is shorter than the varnode's size, add some null bytes:

```python
    if len(bs) < inpt.size:
        bs += '\x00' * (inpt.size - len(bs))
```

Then all we need to do is update our global state

```python
    # Now that we've passed all the prerequisite checks, assume that we've found a stack string
    found_ss = True

    # Merge this instruction into `ss_insns` if it is non-empty
    if len(ss_insns) == 0:
        ss_insns = [(insn.address.offset, insn.address.offset + insn.length)]
    else:
        ss_insns = merge_insns(ss_insns, insn)

    # Store out string in its address space
    set_varnode_value(pc.output, bs)
```

The `merge_insns` function is pretty straightforward, it just merges our current instruction with our previous blocks if any overlap exists. You can look at in the full code if you really want to see it.

#### Handling STORE

We'll structure our STORE-handling procedure a little more like a state machine: 

```python
def handle_store(pc):
    dst = get_varnode_value(pc.getInput(1))
    src = get_varnode_value(pc.getInput(2))

    # Throw out any previously-emulated pcode if we can't resolve the input varnodes
    if src is None or dst is None or type(dst) != str:
        clear_varnodes()
        return

    if src == 0:
        src = '\x00'
```

The reason for the `src == 0` check is that in some cases, just the null terminator is copied into the source varnode. Normally, the source varnode will contain a portion of the stack string; however, when it includes just the null terminator, it will show up as 0 even though we want to include it in our string.

Next, we have to try and parse the register and offset from the destination varnode since we are expecting stack strings to be written to a register:

```python
    if '+' in dst:
        reg, off = dst.split('+')
        off = int(off)
    else:
        reg = dst
        off = 0
```

The reason for the two cases is that when storing to a register directly, the offset will be 0 and there will be no add operation to produce the temporary address.

Now we can deal with updating the global state regarding the current stack string:

```python
    # If `ss_reg` is None, that means this is the first STORE for this stack string so we should set the global register and offset
    if ss_reg is None:
        ss_reg = reg
        ss_off = off
        ss = src

    # If `ss_reg` is not None, but our offset isn't bordering the current stack string, clear the varnodes and continue
    # This is the same overlap calculation as in `merge_insns`
    elif min(ss_off + len(ss), off + len(src)) - max(ss_off, off) < 0:
        clear_varnodes()
        return

    # In this case, we have an existing stack string and we are moving another part of it
    else:
        ss = merge_ss(ss, src, ss_off, off)
        ss_off = min(ss_off, off)

    # Merge the current instruction into our ss_insn blocks
    ss_insns = merge_insns(ss_insns, insn)
```

Here, we in `merge_ss` which contains very similar logic to `merge_insn` expect it merges our existing stack string with the new portion being stored. Again, look at the full source if you're curious.

The only thing we still have to do is reset the global state if our stack string is ending, i.e. there's a null terminator:

```python
    if '\x00' in ss:
        start, end = get_largest_insn_block(ss_insns)
        
        stack_strings[ss] = {
            'start': start,
            'end': end,
            'reg': ss_reg,
            'off': ss_off
        }

        found_ss = False
        ss_reg = None
        ss_off = 0
        ss = ''
        ss_insns = []

        clear_varnodes()
```

Whew! That was a lot. Thankfully that was the hard part (at least code-wise). Now that we can detect all of the stack strings and where they are in our function, we can work on getting them to show up in the decopmiler.

</details>

## Patching the Program

After playing around a little bit with setting data types in the decompiler, I reached the conclusion that Ghidra's decompiler just wasn't built to handle this situation (and I don't blame them -- that'd be pretty crazy if they could account for this). After some thought, I decided that the best way forward was to patch the program with some assembly that Ghidra would know how to interpret.

Let's take a second to talk about what that assembly might look like.

### What to Patch With

We need something where it is obvious to Ghidra that we are moving a string into our target register and offset. What better way than calling `strcpy`? Our plan will be to:

1. Write the string into memory.
2. Call `strcpy` with our reg + off as the destination and stack string as the source.

Things get a little tricky when you start to consider where to place the string. 

We could try to put it at the end of the `__text` or `__data` section since then we'd have to shift around all of the subsequent sections to make room. Doable but not great. 

We also *could* create a new section after all of the existing sections and put our strings there. The problem with that is that if we actually want to run the binary after patching it, we'll need to add a new load command to the Mach-O header. Again, doable, but a lot of unnecessarily work involved.

The obvious answer as to where to put our strings is in the code that was used to create them! The one caveat is that we'll need to jump over each string so we don't try to execute it.

Here's how we'll structure it, assuming our stack string is at `[reg + off]`:

```
    push rsi            ; save all the registers we're going to use
    push rdi
    push rax
    lea rsi, [0x9] ---  ; get our string address into the source register
--- jmp strlen + 2   |  ; jump over the string
|   s            <----
|   t
|   a
|   c
|   k
|
|   s
|   t
|   r
|   i
|   n
|   g
|   \x00
--> lea rdi, [reg + off]  ; get our register + offset into the destination register
    call strcpy           ; call strcpy
    pop rax               ; restore the registers we used
    pop rdi
    pop rsi
```

This patch is fine if not a little long. Remember that all of this needs to fit in the space of the instructions used to construct the stack string. Therefore, there are a few optimizations we can make.

The first we can make is if our offset is 0 (which is the case for our strings in registers allocated by `new`). If the offset is 0, we can change:

```
lea rdi, [reg + off]
```

to

```
push reg
pop rdi
```

We save a whopping 1 byte with this! Here's a massive *2* byte optimization we can make if our register is in `rax` (which again is the case for strings allocated by `new`).

Since `strcpy` returns the destination pointer in `rax`, we don't need to save and restore `rax`. Therefore, we can change

```
lea rdi, [reg + off]
```

to

```
pop rdi
```

since `rax` was the last item pushed onto the stack, if we `pop`, we get our destination pointer into `rdi`. Since `rax` is no longer on the stack, we can also get rid of the `pop rax` instruction after calling `strcpy`.

Now that we know *what* we want to patch with, let's go over the code we'll use to actually apply the patch. Like the code used to detect stack strings, you may want to skip this section. There's nothing groundbreaking, just assembling some instructions and setting some bytes in the binary.

<details>
<summary>The code</summary>

</details>
