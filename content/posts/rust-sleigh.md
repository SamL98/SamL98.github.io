+++
thumbnail = "/ss_thumbnail.png"
title = "Notes on Implementing SLEIGH"
date = 2025-10-28
+++

## Introduction
I recently open-sourced [my implementation](https://github.com/SamL98/rust-sleigh) of a [SLEIGH](https://ghidra.re/ghidra_docs/languages/html/sleigh.html) lifter and given that there's no documentation for how this stuff works, I figured I'd share a bit.

## SLEIGH
SLEIGH is a domain-specific language for generating programs which take machine code and output an intermediate representation (IR) -- referred to as a lifter.
Or rather, when compiled, a SLEIGH specification generates a large XML file defining the instructions, registers, and other aspects of a processor.

This XML file is basically a program which tells the interpreter (described here) how to process the raw bytes.
If you're confused, good. So am I. We've very quickly reached the level of turing machines running turing machines.
Hopefully as this article goes on, things will become clearer.

### Specification Language
To get a feel for the SLEIGH concepts, let's look at the specification before compiling and see how the byte 0x55 will be lifted for the x86-64 architecture (`PUSH RBP`)

If you go into Ghidra, disassemble an x86-64 binary, find a `PUSH RBP` instruction, right click on it, and select "Instruction Info", you'll see some useful information about how the instruction was lifted.

Namely, on the left, there shold be a section titled "Constructor Line #'s" and underneat it should say `PUSH(ia.sinc:3380)`, `Rmr64(ia.sinc:604)` (the line numbers might differ based on your version of Ghidra).

If we open the file `$GHIDRA_PATH/Ghidra/Processors/x86/data/languages/ia.sinc` and go to line 3380, we see the following (re-formatted for nicer reading):

```
:PUSH Rmr64 is $(LONGMODE_ON) & vexMode=0 & addrsize=2 & row=5 & page=0 & Rmr64 {
    push88(Rmr64);
}
```

This line, like the instruction info was telling us, is a constructor.
At its most basic level, a constructor is telling the lifter what IR operations to emit when a specific bit pattern is seen.

Each constructor is made composed like so:

```
<table>:<display> is <pattern> {
    <semantic>
}
```

`<table>` is used for grouping constructors with different bit patterns into the same logical unit (more on this in a moment).
In the case of `PUSH`, the `<table>` is empty, meaning that the constructor is part of the root, `instruction` table.

The `<display>` section defines how the disassembled instruction should be rendered to text.
In the case of `PUSH Rmr64`, each operand will be recursively expanded using their own display sections (e.g. `Rmr64` -> `RBP`) and finally concatenated together into `PUSH RBP`.

The `<pattern>` section defines the bit pattern that matches the constuctor.
Similar to the display section, the patterns of the operands (`Rmr64`) are also recursively expanded and concatenated into the whole bit pattern.
The rest of the variables in the bit pattern (i.e. `vexMode` or `row`) are aliases to bit ranges in either the disassembly context or the raw machine code bytes. 

Finally, the `<semantic>` section says which p-code ops to emit for the disassembled instruction.
In this case, `push88` is actually a p-code macro so the emitted ops will actually be:

```
mysave:8 = Rmr64;
RSP = RSP - 8;
*:8 RSP = mysave;
```

Now taking a look at the second constructor, we see:

```
Rmr64: r64 is rexBprefix=0 & r64 {
    export r64;
}
```

The first thing to notice is that this constructor is part of the `Rmr64` table.
Looking at the next line in the sinc file, we see the other constructor in the table.

```
Rmr64: r64_x is rexBprefix=1 & r64_x {
    export r64_x;
}
```

Therefore, the table mechanism is sort of a way of doing polymorphism on the operands.
The `PUSH` constructor can reference the `Rmr64` table without caring if `rexBprefix` is set or not.

The semantic sections of these constructors also just use the `export` statement.
This won't actually be emitted in the p-code, it is just telling the SLEIGH interpreter to use the value of `r64` or `r64_x` when `Rmr64` is referenced in the semantic section of any parent constructor.

Finally, if we look further up in the file, we see the line:

```
attach variables [ r64 reg64 base64 index64 ] [ RAX RCX RDX RBX RSP RBP RSI RDI ];
```

This means that when we use the value of `r64` (or `reg64` or `base64` or `index64`), we are actually referencing the register at that index in the given array.
That's why in our instruction where `r64` is 5, we are referencing `RBP`.

`r64_x` is attached in a similar way to reference a different list of registers:

```
attach variables [ r64_x reg64_x base64_x index64_x ] [ R8 R9 R10 R11 R12 R13 R14 R15 ];
```

### Compilation
Ghidra doesn't operate on the sinc or slaspec files themselves.
Instead, they are first compile into a sla file.
If you look at the x86-64 sla file (located in the previous directory at `x86-64.sla`), you'll see that it's just an XML file.
Perusing this file will just reveal at lot of meaningless tags so to guide us, I'll draw our attention to line 11935 (again line numbers may vary depending on version):

```
<subtable_sym name="instruction" id="0x0" scope="0x0" numct="2660">
```

This is where the root `instruction` (sub)table is defined.
We can see that `numct`, the number of constructors, is 2660, so there are 2660 different instructions we can disassemble for the architecture.

Immediately after that line, we see the following element (once again re-formatted):

```
1  <constructor parent="0x0" first="1" length="1" line="0:1531">
2     <oper id="0x660"/>
3     <opprint id="0"/>
4     <context_op i="0" shift="21" mask="0xe00000" >
5         <intb val="1"/>
6     </context_op>
7     <construct_tpl>
8         <null/>
9         <op_tpl code="BUILD">
10            <null/>
11            <varnode_tpl>
12                <const_tpl type="spaceid" name="const"/>
13                <const_tpl type="real" val="0x0"/>
14                <const_tpl type="real" val="0x4"/>
15            </varnode_tpl>
16        </op_tpl>
17    </construct_tpl>
18 </constructor>
```
Looking at the referenced line in `ia.sinc` (1531), we see the following constructor:

```
:^instruction is instrPhase=0 & over=0x2e; instruction [ segover=1; ] {} # CS override
```

We can see that I lied previously and there's an extra, optional section to a constructor, found between the square brackets.
This is the `<actions>` section and specifies changes to the disassembly context or constructor-local computations.
This corresponds to lines 4-6 of the above XML snippet.

We see the display section (`^instruction`) on line 3 as an `opprint` command to print the first operand.
These operands are specified in a list above the print commands (on line 2).

Every object (subtable, operand, varnode, etc.) in SLEIGH has an id associated with it.
In the operand on line 2's case, it's pointing to the object with id 0x660.
Searching for that id in the sla file shows the following:

```
<operand_sym name="instruction" id="0x660" scope="0x129" subsym="0x0" off="1" base="-1" minlen="0" index="0">
    <operand_exp index="0" table="0x0" ct="0x0"/>
</operand_sym>
```

Which is saying that the operand is referencing 0-th subsymbol, or again the `instruction` subtable:

```
<subtable_sym_head name="instruction" id="0x0" scope="0x0"/>
```

This is because x86 instructions can have a variable number of prefix bytes.

Also note that we don't care about the `operand_exp` element inside of the `operand_sym`. This could be some extra information that comes in handy in some cases but from my experience, there is a lot of redundant or unused information in sla files.

Going back to the constructor snippet, lines 7-17 define a `constructor_tpl` (`tpl` is short for template in SLEIGH parlance).

This is where the semantic section of the constructor is.

Even though the semantic section of the constructor in the sinc file is empty, there is a `BUILD` `op_tpl` in the semantic section.
This is because constructor operands each have their own semantic sections which need to be emitted along with the p-code for the current constructor.
This is done using the `BUILD` opcode to paste the generate p-code for the specified operand at that location.

### Decisions
There's still a lot I haven't covered, but let's move on for now.
Astute readers might have noticed that the pattern section is seemingly missing from the constructor previously shown.

This is because for every subtable, the SLEIGH compiler takes every bit pattern and converts them into a decision tree.
Each leaf of this tree corresponds to a constructor in the subtable.
This is presumably done for space efficiency.

If we search for `decision` in the sla file, we'll find how the decision tree for the `instruction` subtable is defined:

```
<decision number="2845" context="false" start="0" size="4">
    <decision number="1283" context="false" start="4" size="4">
        <decision number="6" context="true" start="20" size="1">
            <decision number="3" context="false" start="0" size="0">
                <pair id="17">
                    <context_pat>
                        <pat_block offset="0" nonzero="4">
                          <mask_word mask="0x8c000001" val="0x8000000"/>
                        </pat_block>
                    </context_pat>
                </pair>
                <pair id="70">
                    <combine_pat>
                        <context_pat>
                            <pat_block offset="2" nonzero="3">
                              <mask_word mask="0x8008000" val="0x0"/>
                            </pat_block>
                        </context_pat>
                        <instruct_pat>
                            <pat_block offset="0" nonzero="2">
                              <mask_word mask="0xffc00000" val="0xc00000"/>
                            </pat_block>
                        </instruct_pat>
                    </combine_pat>
                </pair>
                ...
```

At each level of the tree, we take `size` bits at `start` from either the context or instruction bits
and use that as an index into the next level.

At the last level, the rest of the bit pattern is matched using more complex masks.

## Resolving
Now that we now a bit more about the internals of SLEIGH, let's talk about how to implement a SLEIGH interpreter.
The interpreter will be made in two stages: resolving and building.

The first step, resolving, is determining which constructor and operands are generated from specific machine code with a specific disassembly context.
We'll store the result of the resolving in the following enum:

```rust
pub enum MatchedSymbol<'a> {
    Constructor(&'a Constructor, Vec<MatchedSymbol<'a>>),
    Symbol(&'a Symbol, usize),
    Literal(i64, usize),
    String(&'a str),
}
```

Then we can resolve symbols like:

```rust
fn resolve_symbol<'a, 'b>(
    data: &[u8],
    pc: u64,
    sym: &'a Symbol,
    ctx: &mut ResolveContext<'a, 'b>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    match &sym.body {
        SymbolBody::Subtable(table) => {
            resolve_constructor(data, table, ctx)
            .map(|ct| {
                resolve_operands(data, pc, ct, ctx)
                .map(|(operands, ops_len)| {
                    let ct_len = (ct.length * 8) as usize;
                    let bit_len = ct_len.max(ops_len);
                    let matched_sym = MatchedSymbol::Constructor((ct, operands));
                    (matched_sym, bit_len)
                })
            })
            .flatten()
        },
        ...
    }
}
```

where we pass the instruction symbol to start resolving:

```rust
resolve_symbol(data, pc, &lang.symbols[lang.insn_table_id], ctx);
```

In `resolve_constructor`, we walk the decision tree to find which the index of the correct constructor:

```rust
fn resolve_constructor<'a, 'b>(
    words: &[u8],
    table: &'a Subtable,
    ctx: &ResolveContext<'a, 'b>,
) -> Option<&'a Constructor> {
    let mut dtree = &table.decision_tree;

    loop {
        match dtree {
            DecisionTree::NonLeaf((is_context, start, size, children)) => {
                if children.len() == 0 {
                    return None;
                }

                if *size == 0 && children.len() == 1 {
                    dtree = &children[0];
                    continue;
                }

                let bit_start = 32 - (start + size);

                let idx = if !is_context {
                    let word = get_word(words, 0, 4) as u32;
                    (word >> bit_start) & ((1 << size) - 1)
                } else {
                    let ctx_word = ctx.ctx[(*start as usize) / 32];
                    ctx_word.overflowing_shr(bit_start).0 & ((1 << size) - 1)
                } as usize;

                dtree = &children[idx.min(children.len() - 1)];
            }
            DecisionTree::Leaf(pairs) => {
                for (ct_id, pattern) in pairs {
                    let ct = &table.constructors[*ct_id as usize];

                    if match_pattern(pattern, &words, ctx) {
                        return Some(ct);
                    }
                }

                return None;
            }
        };
    }
}
```

And we resolve the operands by evaluating each of their expressions, possibly recursively resolving subtables.

```rust
fn resolve_operands<'a, 'b>(
    words: &[u8],
    pc: u64,
    ct: &'a Constructor,
    ctx: &mut ResolveContext<'a, 'b>,
) -> Option<(Vec<MatchedSymbol<'a>>, usize)> {
    let mut matched_ops = vec![];
    let mut bit_ends = vec![];

    for op_idx in &ct.operands {
        let operand = get_operand(&op_idx, &ctx.lang.symbols);

        match &operand.expr {
            Some(Expr::Field(Field::Token(expr))) => {...},
            Some(Expr::Field(Field::Context(expr))) => {...},
            Some(Expr::Unary(_) | Expr::Binary(_)) => {...},
            Some(Expr::Const(val)) => {...},
            None => {
                let op_sym = &ctx.lang.symbols[&operand.subsym];

                let base = if operand.base < 0 {
                    operand.off as usize
                } else {
                    bit_ends[operand.base as usize] / 8
                };

                // Before recursively resolving a symbol, we first need to modify the context.
                for op in &ct.context_ops {
                    let existing = ctx.ctx[op.i as usize];
                    let mask = op.mask;

                    let (val, _, _) = evaluate_expr(&op.expr, &ctx.ctx, &matched_ops, &ctx.reg_space);
                    let v = (val as u32) << op.shift;
                    ctx.ctx[op.i as usize] = (existing & !mask) | (v & mask);
                }

                match resolve_symbol(&words[base..], pc + base as u64, op_sym, ctx) {
                    Some((matched_sym, sub_bit_end)) => {
                        let op_bit_end = (base * 8) as usize + sub_bit_end;
                        matched_ops.push(matched_sym);
                        bit_ends.push(op_bit_end);
                    },
                    None => {
                        return None;
                    },
                };
            },
        }
    }

    let bit_len = bit_ends.into_iter().max().unwrap_or(0);
    Some((matched_ops, bit_len))
}
```

Obviously I've left a lot of code out but this should give you the gist.
To see all of the gory detail, check [this](https://github.com/SamL98/rust-sleigh/blob/master/src/symbol_resolver.rs) out.

If we now pass the byte 0x55 through the resolver, we get the following matched symbol with the same matched constructors as ghidra:

```
instruction (line 3380)
  Rmr64 (line 604)
    RBP
```

And if we look at a more complicated instruction, like `[f3, 0f, 11, 87, 68, 81, 20, 00]`,
we see that it disassembles to instruction `MOVSS dword ptr [RDI + 0x208168], XMM0` and has the following parse tree:

```
instruction (line 1540)
  instruction (line 5915)
    m32 (line 805)
      Mem (line 790)
        segWide (line 759)
        addr64 (line 738)
          Rmr64 (line 604)
            RDI
          simm32_64 (line 659)
            0x208168:4
    XmmReg (line 614)
      XMM0
```

## Building
Now that we can generate the parse tree for a sequence of bytes, we need to generate the p-code for the matched constructor.

Going back to the `PUSH RBP` instruction, let's again print out the parse tree but this time also printing out the constructor templates:

```
instruction (line 3380)
    BUILD(const:0:4)
    unique:ef80:8 = COPY(Handle#0)
    register:20:8 = INT_SUB(register:20:8, const:8:8)
    STORE(const:ram:8, register:20:8, unique:ef80:8)

  Rmr64 (line 604)
      *[Handle#0:Handle#0](0:Handle#0:0)

    RBP
```

Much of the first template should look reasonable, i.e. the `COPY`, `INT_SUB`, and `STORE` operations.
These are what we would expect the `PUSH` instruction to be doing.

Things get a little confusing when we look at the operand of the `COPY` operation, `Handle#0`.

See, remember that each constructor can export a value.
In fact, here's the `Rmr64` constructor on line 604 again:

```
Rmr64: r64 is rexBprefix=0 & r64 {
    export r64;
}
```

So when we're referencing `Handle#0`, we're referencing the value exported by the 0-th operand.

This is `*[Handle#0:Handle#0](0:Handle#0:0)` which corresponds to the `export r64` statement.

I'm going to try to explain what this means but I did a good bit of guesswork when implement this part and I know my understanding isn't 100% correct.
Hopefully I'll go back soon and actually re-read the relevant ghidra code to figure out what's going on but for now, I'm just going to do my best.
That being said, this part of the interpreter seems to work so that's something.

Anyways, exported handles can be "dynamic".
You can think of this as basically meaning that the handle is a pointer.
Whenever this dynamic handle is read or written to, we're actually going to read or write to the pointed to memory.

To make this more concrete, let's look at the parse tree with the constructor templates for the more complicated `MOVSS` instruction:

```
instruction (line 1540)
    BUILD(const:0:4)

  instruction (line 5915)
      BUILD(const:1:4)
      BUILD(const:0:4)
      Handle#0 = COPY(Handle#1:Handle#1:4)

    m32 (line 805)
        *[ram:4](Handle#0)
        BUILD(const:0:4)

      Mem (line 790)
          *[Handle#1:Handle#1](0:Handle#1:0)
          BUILD(const:1:4)
          BUILD(const:0:4)

        segWide (line 759)
            *[const:8](0:0:0)

        addr64 (line 738)
            *[unique:Handle#0](0:3200:0)
            BUILD(const:1:4)
            BUILD(const:0:4)
            unique:3200:Handle#0 = INT_ADD(Handle#0, Handle#1)

          Rmr64 (line 604)
              *[Handle#0:Handle#0](0:Handle#0:0)

            RDI

          simm32_64 (line 659)
              *[const:8](Handle#0:Handle#0:0)

            208168:4

    XmmReg (line 614)
        *[Handle#0:Handle#0](0:Handle#0:0)

      XMM0
```

We can see that aside from the `BUILD` ops, the main instruction (on line 5915) only has a `COPY` op even though clearly the instruction `MOVSS dword ptr [RDI + 0x208168], XMM0` writes to memory.
Looking at the sinc file, we see this confirmed:

```
:MOVSS m32, XmmReg is vexMode=0 & $(PRE_F3) & byte=0x0F; byte=0x11; m32 & XmmReg ... {
    m32 = XmmReg[0,32];
}
```

However, if we look at the `m32` matched constructor on line 805, we see that the exported handle has the `ram` address space -- `*[ram:4](Handle#0)`.

Again looking at line 805 in the sinc file confirms this:

```
m32: "dword ptr" Mem is Mem {
    export *:4 Mem;
}
```

Going back to the `PUSH RBP` example and `*[Handle#0:Handle#0](0:Handle#0:0)`, it seems to me that this format where the pointer and offset are taken from the handle while the address space and size are zero is a special case meaning that just the regular varnode is exported.
This also seems to be the case with the matched `Mem` constructor on line 790.
This is one of those cases where I don't think the SLEIGH compiler authors intended for this to be hardcoded as a special case but it turns out to be true in the way that they generated the sla file.

Anyways, the birds-eye-view of the building process will be to recursively build all of the operands (in order to obtain the exported handles and emitted p-code), then build the final p-code by pasting the operand p-code from the `BUILD` directives while substituting any handle variables with the handles that we just built.

In code, this looks roughly like:

```rust
fn build_sym<'a>(
    matched_sym: &'a MatchedSymbol,
    ctx: &BuildContext,
) -> (Vec<PcodeOp>, Option<PcodeObject>) {
    let mut op_pcode = vec![];
    let mut op_handles = vec![];

    let mut pcode = vec![];
    let mut handle = None;

    match matched_sym {
        MatchedSymbol::Symbol(sym, _) => {...},       // Set handle to varnode symbol,
        MatchedSymbol::Literal((val, size)) => {...}, // Set handle to const varnode.
        MatchedSymbol::Constructor((ct, operands)) => {
            // First build the operands.
            for op in operands {
                let (mut op_ops, op_hnd) = build_sym(op, ctx);
                op_handles.push(op_hnd.unwrap_or(PcodeObject::Dummy));
                op_pcode.push(op_ops);
            }

            let template = ct.template.as_ref().unwrap();

            // Then build the p-code.
            for stmt in &template.statements {
                if let ConsTemplate::Op(op_template) = stmt {
                    if op_template.code == "BUILD" {
                        if let ConstTemplate::Val(op_idx) = op_template.inputs[0].offset_template {
                            let mut op_ops = op_pcode[op_idx as usize].clone();
                            pcode.append(&mut op_ops);
                        }
                    }
                    else {
                        let uniq = (start_op_idx + num_ops) as i32;
                        let mut built_ops = build_pcodeop(
                            SeqNum::from(ctx.pc, uniq),
                            &op_template,
                            ctx,
                        );
                        pcode.append(&mut built_ops);
                    } 
                }
            }

            // Build the exported handle if there is one.
            for stmt in &template.statements {
                if let ConsTemplate::Handle(handle_template) = stmt {
                    let my_handle = build_handle(&handle_template, op_handles, ctx);
                    handle = Some(my_handle);
                    break;
                }
            }
        },
    }

    (pcode, handle)
}
```

Where in `build_pcodeop`, we have to handle the dynamic handles and therefore can produce multiple ops:

```rust
fn build_pcodeop<'a>(
    mut seq: SeqNum,
    op_tpl: &'a OpTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> Vec<PcodeOp> {
    let mut opcode = op_tpl.code.as_str();
    let mut inputs = vec![];
    let mut output = None;
    let mut ops = vec![];

    for tpl in op_tpl.inputs {
        if let Some(idx) = tpl.handle_index() {
            match &objs[idx] {
                PcodeObject::Varnode(vn) => inputs.push(vn.clone()),
                PcodeObject::Handle(h) => {
                    if !h.temp.space.is_dummy() {
                        ops.push(PcodeOp::new(
                            seq,
                            "LOAD",
                            vec![Varnode::dummy(), h.pointer.clone()],
                            Some(h.temp.clone()),
                        ));

                        inputs.push(h.temp.clone());
                        seq = seq.next();
                    } else {
                        inputs.push(h.pointer.clone());
                    }
                },
                _ => panic!(),
            };
        } else {
            let vn = build_varnode(tpl, objs, ctx);
            inputs.push(vn);
        }
    }

    if let Some(tpl) = &op_tpl.output {
        if let Some(idx) = tpl.handle_index() {
            match &objs[idx] {
                PcodeObject::Varnode(vn) => output = Some(vn.clone()),
                PcodeObject::Handle(h) => {
                    if !h.temp.space.is_dummy() {
                        let mut output = Some(h.temp.clone());
                        ops.push(PcodeOp::new(
                            seq,
                            opcode,
                            inputs.clone(),
                            output,
                        ));

                        opcode = "STORE";
                        inputs = vec![Varnode::dummy(), h.pointer.clone(), h.temp.clone()];
                        seq = seq.next();
                    } else {
                        output = Some(h.pointer.clone());
                    }
                },
                _ => panic!(),
            };
        } else {
            let vn = build_varnode(tpl, objs, ctx);
            output = Some(vn);
        }
    }

    ops.push(PcodeOp::new(seq, opcode, inputs, output));
    op
}
```

Now our instructions should have the correct p-code:

```
[55]
0x100005bb0:0: Uef80:8 = RBP
0x100005bb0:1: RSP = RSP - 0x8:8
0x100005bb0:2: *RSP = Uef80:8

[f3, 0f, 11, 87, 68, 81, 20, 00]
0x100005beb:0: U3200:8 = RDI + 0x208168:8
0x100005beb:1: U5480:4 = XMM0_Da
0x100005beb:2: *U3200:8 = U5480:4
```

### Building Text
The only thing we now have to do is use the constructor's display section to generate the instruction's assembly.

We can do this fairly trivially by iterating over the constructor's print commands and printing either the string literal piece or recursively generating the text for the operand:

```rust
fn build_cmd_text(cmd: &PrintCommand, operands: &Vec<MatchedSymbol>) -> String {
    match cmd {
        PrintCommand::Op(op_idx) => build_text(&operands[*op_idx as usize]),
        PrintCommand::Piece(piece) => piece.clone(),
    }
}

pub fn build_text(matched_sym: &MatchedSymbol) -> String {
    let mut text = String::new();

    match &matched_sym {
        MatchedSymbol::Constructor((ct, operands)) => {
            if let Some(cmds) = &ct.print_commands {
                for cmd in cmds {
                    text.push_str(&build_cmd_text(cmd, &operands));
                }
            }
        },
        MatchedSymbol::Symbol(sym, _) => {
            if let SymbolBody::Varnode(vnode) = &sym.body {
                text.push_str(&vnode.name);
            }
        },
        MatchedSymbol::Literal((val, sz)) => {
            let mut v = *val as u64;
            let mut sign_str = "";

            // ... fixups for negative numbers ...
            text.push_str(format!("{}0x{:x}", sign_str, v).as_str());
        },
        MatchedSymbol::String(s) => {
            text.push_str(&s);
        }
    }

    text
}
```

And now we should get the p-code along with the assembly for our lifted instructions:

```
[55]
0x100005bb0: PUSH RBP
    0x100005bb0:0: Uef80:8 = RBP
    0x100005bb0:1: RSP = RSP - 0x8:8
    0x100005bb0:2: *RSP = Uef80:8

[f3, 0f, 11, 87, 68, 81, 20, 00]
0x100005beb: MOVSS dword ptr [RDI + 0x208168], XMM0
    0x100005beb:0: U3200:8 = RDI + 0x208168:8
    0x100005beb:1: U5480:4 = XMM0_Da
    0x100005beb:2: *U3200:8 = U5480:4
```

## Conclusion
This has been for me, and I can only imagine for the reader too, a long, arduous, and confusing journey through subtables, constructors, operands, handles, and more.

I hope you've come away knowing a little more about SLEIGH or at least appreciating a bit its weirdness and occasional elegance.

[Here](https://github.com/SamL98/rust-sleigh)'s another link to the full code in case you don't want to scroll back up and if you have any questions, don't hesitate to email me.
