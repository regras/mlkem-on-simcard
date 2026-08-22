# MLKEM Applet Organization

Due to the overhead that multiple classes and objects introduce, as described in the article, the entire ML-KEM logic is present in a single class.
To facilitate the visualization and understanding of the code, each execution logic was separated by a comment separator, which describes the type of the following operations.
Among the types, are these:

- **Standard Java Card Functions (lines 245-443)**: Standard Java Card functions, such as applet installation, selection, and APDU command processing.
- **SHAKE and SHA3 (lines 444-919)**: SHAKE and SHA3 hash functions, used to generate pseudo-random arrays from seeds.
- **NTT Operations (lines 920-1,038)**: Number Theoretic Transform (NTT) functions, used to accelerate polynomial operations.
- **Polynomial Operations (lines 1,039-1,519)**: Functions for polynomial manipulation, including addition, subtraction, multiplication, and reduction.
- **Byte Operations (lines 1,520-1,605)**: Functions for byte manipulation, including byte-to-int conversion and vice versa.
- **Indistinguishability under Chosen Plaintext Attack (IND-CPA) (lines 1,606-2,203)**: Functions for key generation, key encapsulation, and decapsulation, ensuring security against chosen plaintext attacks.
