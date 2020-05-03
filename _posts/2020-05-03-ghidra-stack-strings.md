---
layout: post
title:  "Decompiling Stack Strings in Ghidra"
date:   2020-05-03 15:30:10 -0500
categories: jekyll update
---

In this post, I'll be discussing a method I recently implemented to have stack strings show up in Ghidra's decompiler window. The final script transforms this garbage:

![orig_ss_example](/images/original_ss_example.png)

into this, moderately better garbage:

~[new_ss_example](/images/processed_ss_example.png)
