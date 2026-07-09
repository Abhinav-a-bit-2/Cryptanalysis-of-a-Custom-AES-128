=========================================================
1) AES: S-BOX GENERATION USING SWAPPING BITS OF GF INTEGERS

Overview

This project implements a custom Dynamic Substitution Box
(S-Box) architecture to defend Advanced Encryption Standard
(AES) against Differential Fault Analysis (DFA).

Instead of using a static, hardcoded lookup table, the
S-Box is regenerated on the fly. The structure of the S-Box
is mathematically tethered to the encryption key, forcing
an attacker to brute-force billions of mathematical anomalies
(Ghost Keys) to crack the cipher.

Inputs to the Generator

Base S-Box: The standard FIPS-197 AES 256-byte array.

Dynamic Key (dyn_key): An 8-bit integer (0 to 255).

=========================================================
STEP 1: THE XOR FOLD (Generating the dyn_key)

To ensure the S-Box is tied to the current state of the
cipher without exceeding memory constraints, the 128-bit
(16-byte) sub-key is compressed into a single 8-bit value
using a sequential XOR fold.

Algorithm:

Start with an 8-bit result = 0.

Loop through all 16 bytes of the current Round Key.

XOR each byte into the result.

The final 8-bit result is the "dyn_key".

=========================================================
STEP 2: THE PERMUTATION ARRAY (Swapping Logic)

The dyn_key acts as a control switch for an 8-element
array that dictates how the bits inside the S-Box will be
scrambled.

Algorithm:

Initialize an array of columns: cols = [0, 1, 2, 3, 4, 5, 6, 7]

Loop through a counter 'i' from 0 to 7:
a. Check the 'i-th' bit of the dyn_key.
b. If the bit is 1:

Calculate the next index: swap_idx = (i + 1) % 8

Swap the values at cols[i] and cols[swap_idx].
c. If the bit is 0:

Do nothing. Continue loop.

Example:
If dyn_key = 1 (binary 00000001), the 0th bit is 1.
The array swaps index 0 and 1, becoming: [1, 0, 2, 3, 4, 5, 6, 7]

=========================================================
STEP 3: BIT-LEVEL SCRAMBLING (Generating the New S-Box)

Using the scrambled 'cols' array from Step 2, the generator
rewires every single byte in the standard AES S-Box.

Algorithm:

Initialize an empty 256-byte dynamic_sbox array.

Loop through every value 'val' from 0 to 255:
a. Get the original AES byte: orig_val = base_sbox[val]
b. Initialize a new_val = 0.
c. Loop through a counter 'i' from 0 to 7:

Look at the target bit position: target = cols[i]

Extract that target bit from orig_val.

Shift that extracted bit to the 'i-th' position.

OR it into new_val.
d. Store new_val into dynamic_sbox[val].

=========================================================
CRYPTOGRAPHIC IMPACT (Why this defeats DFA)

Because the bits are shuffled based on an XOR fold of the
entire 128-bit key, the columns of the AES matrix become
algebraically coupled.

An attacker attempting a Differential Fault Analysis (DFA)
cannot solve the cipher one column at a time. They are
forced to guess the S-Box structure, creating a massive
Cartesian cross-multiplication problem. This inflates the
attacker's search space from a few dozen candidates to over
100 million false-positive "Ghost Keys" per algorithmic branch,
causing their solver to hit a memory and CPU wall.


=======================================================
2) AES: S-BOX GENERATION USING SUBSTITUTING BITS OF S-BOX USING KNOWN LIST
OVERVIEW
This project implements a custom variant of the Advanced Encryption Standard (AES-128). Unlike standard AES, which uses a single, static 256-byte Rijndael S-box for all non-linear substitutions, this architecture utilizes a bank of multiple S-boxes. The specific S-box applied to any given byte is determined dynamically based on the byte's spatial position.

RULE 1: THE S-BOX BANK
The cipher requires a pre-defined bank of mathematically valid 256-byte S-boxes.

In this implementation, there are 16 distinct S-boxes.

They are stored as a 2D array: SBOX[16][256].

RULE 2: THE SELECTOR ARRAY (N)
The mapping of which S-box to use is controlled by a 16-element configuration array called 'n'.

Example: n = [13, 15, 10, 7, 6, 5, 3, 8, 2, 11, 4, 0, 14, 9, 1, 12]

Each value in 'n' represents an index (0 to 15) pointing to a specific S-box in the S-box bank.

This array must be known by both the encryptor and decryptor (acting as a public configuration or secondary key material).

RULE 3: STATE SUBSTITUTION (SubBytes)
During the encryption and decryption rounds, the 16-byte state matrix undergoes substitution. The choice of S-box is strictly tied to the physical index of the byte within the state (0 through 15).

For a byte at state index 'i':
Substitute value = SBOX[ n[i] ][ state[i] ]

Example: state[0] will ALWAYS be substituted using SBOX[ n[0] ]. state[15] will ALWAYS be substituted using SBOX[ n[15] ].

RULE 4: DYNAMIC KEY EXPANSION (SubWord) - CRITICAL
The standard AES Key Expansion applies a SubWord function every 4 words. In this custom architecture, the S-box applied to the key bytes depends on the ABSOLUTE BYTE INDEX of the expanded key stream, modulo 16.

The expanded key consists of 44 words (176 bytes total).

When expanding word 'i' (where i is a multiple of 4), the algorithm substitutes 4 bytes.

The absolute byte position of the start of word 'i' is: pos = (i * 4).

The S-box selected for the 'j-th' byte of this word (where j is 0, 1, 2, or 3) is calculated as:
S-box Index = n[ (pos + j) modulo 16 ]

Example for Word 40 (Round 10 Key generation):
Word 40 starts at absolute byte index 160.
Byte 0 uses SBOX[ n[ (160 + 0) modulo 16 ] ] -> SBOX[ n[0] ]
Byte 1 uses SBOX[ n[ (160 + 1) modulo 16 ] ] -> SBOX[ n[1] ]
Byte 2 uses SBOX[ n[ (160 + 2) modulo 16 ] ] -> SBOX[ n[2] ]
Byte 3 uses SBOX[ n[ (160 + 3) modulo 16 ] ] -> SBOX[ n[3] ]

This absolute positioning ensures that mathematical inversion (like deriving Key 9 from Key 10 for cryptanalysis) remains predictable.

RULE 5: INVERSE OPERATIONS (Decryption)
Decryption follows the exact same positional rules, but uses an Inverse S-Box bank.

The INV_SBOX[16][256] array is generated during initialization.

If SBOX[x][y] = z, then INV_SBOX[x][z] = y.

InvSubBytes applies: state[i] = INV_SBOX[ n[i] ][ state[i] ]

====================================================================
SECURITY NOTE FOR CRYPTANALYSIS
Because the positional mapping (modulo 16) aligns perfectly with the 16-byte boundaries of the AES round keys, partial bytes of Round Key 9 can be algebraically decoupled and derived directly from Round Key 10 without needing the entire 128-bit key. This allows Differential Fault Analysis (DFA) attacks to bypass the dynamic obfuscation using targeted Round 8 fault injections.
