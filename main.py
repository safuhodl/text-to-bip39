#!/usr/bin/python3

import argparse
import binascii
import hashlib
import sys

DERIVATION_ALGO = "sha512"
DERIVATION_ITER = 2**20
DERIVATION_DKLEN = 32

WORD_COUNTS = [12, 15, 18, 21, 24]

def load_wordlist():
    with open("english.txt") as f:
        return [word.rstrip() for word in f.readlines()]

def derive_entropy(key: str, pool_index: int, word_count: int):
    if pool_index < 0 or pool_index >= 2**8:
        raise Exception("pool index must fit into one unsigned byte")
    dklen = int(word_count + word_count / 3)
    salt = int.to_bytes(pool_index, 1, "big")
    digest = hashlib.pbkdf2_hmac(
            hash_name=DERIVATION_ALGO,
            password=key.encode("utf-8"),
            salt=salt,
            iterations=DERIVATION_ITER,
            dklen=dklen)
    return digest

def fingerprint(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:8].upper()

def entropy_to_mnemonic(wordlist, data: bytes) -> (list, list):
	if len(data) not in [16, 20, 24, 28, 32]:
		raise ValueError(
		"Data length should be one of the following: [16, 20, 24, 28, 32], but it is not (%d)."
		% len(data)
		)
	h = hashlib.sha256(data).hexdigest()
	b = (
		bin(int.from_bytes(data, byteorder="big"))[2:].zfill(len(data) * 8)
		+ bin(int(h, 16))[2:].zfill(256)[: len(data) * 8 // 32]
	)
	result = []
	indices = []
	for i in range(len(b) // 11):
		idx = int(b[i * 11 : (i + 1) * 11], 2)
		result.append(wordlist[idx])
		indices.append(idx)
	return (result, indices)

def mnemonic_to_seed(mnemonic, passphrase=""):
    bin_seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), ("mnemonic" + passphrase).encode("utf-8"), 2048)
    return bin_seed

def format_mnemonic(words, indices):
    for i, (word, index) in enumerate(zip(words, indices)):
        print("{:>2}.\t{:>4}\t{}".format(i+1, index, word))

def parse_args():
    parser = argparse.ArgumentParser("Derive BIP39 wordlists from a UTF-8 secret")
    parser.add_argument("index", type=int, metavar="INDEX",
            help="Derive with the given index [0..255]")
    parser.add_argument("--fingerprint",
            help="Expect the secret to have this fingerprint (fail otherwise)")
    parser.add_argument("--size", choices=WORD_COUNTS, default=24, type=int,
            help="How many words the derived mnemonic should have (default 24)")
    return parser.parse_args()

def main():
    args = parse_args()
    wordlist = load_wordlist()

    if args.size not in WORD_COUNTS:
        print("ERROR: the mnemonic size has to be one of: {}".format(WORD_COUNTS))
        return

    print("Enter the secret (UTF-8 text) to derive from: ")
    secret = sys.stdin.readline().rstrip()
    index = args.index

    clear_line_code = "\033[1A[\033[2K"
    print(clear_line_code)

    secret_fingerprint = fingerprint(secret)
    print("Secret fingerprint:\t{}".format(secret_fingerprint))
    if args.fingerprint and secret_fingerprint != args.fingerprint.upper():
        print("ERROR: the secret fingerprints do not match")
        return

    entropy = derive_entropy(secret, index, args.size)
    words, indices = entropy_to_mnemonic(wordlist, entropy)

    mnemonic_fingerprint = fingerprint(" ".join(words))
    print("Mnemonic fingerprint:\t{}".format(mnemonic_fingerprint))

    print()
    format_mnemonic(words, indices)

if __name__ == "__main__":
    main()
