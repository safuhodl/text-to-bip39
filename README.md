# BIP39 Mnemonic Generator

The purpose of this program is to deterministically generate BIP39 mnemonics
from arbitrary UTF-8 sequences. Each unique sequence can derive up to 256 child
mnemonics. This program aims to deliver a result similar to BIP85 using only
standard tools (e.g. no elliptic curve operations on secp256k1).

### Derivation Algorithm

The derivation algorithm is as follows:

1. Decode the passed secret (UTF-8 string) into bytes
2. Decode the passed child index (integer) into a single byte [0x00, 0xFF]
3. Stretch the secret using PBKDF2-HMAC into a 32 byte sequence where:
  - hashing algorithm is SHA512
  - password is the decoded secret from step 1.
  - salt is the index byte from step 2.
  - number of iterations is 2^20
  - dkLen is 32 bytes
4. Use the resulting bytes to generate a 24 word mnemonic according to the
    BIP39 standard

### Usage

```bash
$ python3 main.py <CHILD_INDEX> # index is between 0 and 255 inclusive

```

Use the `--help` switch for additional options and safety features.

### Safety Features

To prevent the possibility of passing a secret with a typographic error
it is possible to pass the expected fingerprint of the secret, which has
to be known beforehand. The fingerprint is defined as the first 4 bytes
of the SHA256 digest of the secret (8 characters hex encoded).

## Caution

DO NOT USE FOR STORING REAL MONEY WITH NON-RANDOMLY GENERATED STRINGS.
IN ORDER TO BE SAFE, THE INITIAL ENTROPY HAS TO BE GENERATED RANDOMLY.

A safe way to use this is to generate an original passphrase using dice
or a similar method, somehow encode that into a memorable text sequence
and use that text to derive child mnemonics.

