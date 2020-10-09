---
layout: post
title:  "Attempting a Power Analysis attack on KeeLoq"
date:   2020-08-30 18:30:00 -0500
categories: jekyll update
---

This is sort of a notebook describing my currently failed attempt to recover the key from an [HCS361](link to datasheet). For information on the encoder itself and how it works, take a look at my previous blog post [here](link to medium).

# Description of the Attack

If you've read the [paper](link to paper), you'll know that I'll be attempting a correlation power analysis (CPA). This works by finding the key which generates the expected power (current) consumption that best correlates with that actually observed. The reason this attack is feasible is that the expected power consumption at round of KeeLoq is only dependent on the round. Therefore, we can (in theory) determine one bit of the key at a time. However, in practice, people usually bruteforce multiple bits of the key at once so that the best subkey will correlate much higher than the second best subkey.

# Capturing Power Traces

This is obviously the most crucial part of the algorithm, and one that requires special hardware. I initially bought a [ChipWhisperer Nano](link to CWNANO) but found it too difficult to get align its synchronous sampling with the clock of the encoder. Thankfully, a coworker lent me an [Analog Discovery 2](link to AD2) (thanks, Kuba!) which I've been using for the time being.

## Setting up the Circuit

As described in the paper, we'll put a shunt resistor in the ground path of the encoder. I had no clue how much resistance to put here so I used 10 ohms. Maybe that's why I haven't succeeded but I doubt it.

Anyways, I also connected the Vcc pin to the 3.3V output of my trusty Arduino Uno. Then I've got the data pin connected to the Arduino's GPIO to read the ciphertext and the S1 (double check) button pin to trigger the encryption.

Here's a circuit diagram: ![circuit](circuit diagram)

Then we've got to hook up the oscilloscope part of the AD2 to measure the voltage across the shunt. One other thing I did was attach one of the AD2's digital inputs to the trigger sent by the Arduino so that I have a good anchor to align power traces with.

Here's a picture of the whole setup: ![lab setup](lab setup)

## Analyzing the First Trace

Setting the samplerate to something small like 1MHz so that we get a global picture, we can see a traces somewhat similar than that in the paper: ![global trace comparison](global trace comparison)

The paper's authors say that the encryption happens directly after three peaks (which are writing to the EEPROM) so let's zoom in on that section: ![encryption part](encryption trace)

