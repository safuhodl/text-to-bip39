from main import *

WORDLIST = load_wordlist()

def assert_equals(
        secret,
        index,
        expected_secret_fingerprint,
        expected_mnemonic_fingerprint,
        expected_mnemonic):
    assert fingerprint(secret) == expected_secret_fingerprint
    entropy = derive_entropy(secret, index)
    words, indices = entropy_to_mnemonic(WORDLIST, entropy)
    computed_mnemonic = " ".join(words)
    assert fingerprint(computed_mnemonic) == expected_mnemonic_fingerprint
    assert computed_mnemonic == expected_mnemonic


# test vector #1
secret, index, secret_fingerprint, mnemonic_fingerprint = "some super secret sentence no one can guess", 65, "A847EB44", "2D2AAA78"
mnemonic = "buffalo above surge foam eye volume chicken kingdom render fury model truth express horror slide disagree spare swamp sauce please success various neither chalk"
assert_equals(secret, index, secret_fingerprint, mnemonic_fingerprint, mnemonic)

# test vector #2
secret, index, secret_fingerprint, mnemonic_fingerprint = "a", 48, "CA978112", "EC42ED3D"
mnemonic = "depend crop monitor park chapter enough orbit defense arctic can broken gym bottom home grid anchor beauty social diet culture attack cheese popular science"
assert_equals(secret, index, secret_fingerprint, mnemonic_fingerprint, mnemonic)

# test vector #3
secret, index, secret_fingerprint, mnemonic_fingerprint = "", 48, "E3B0C442", "E263AA84"
mnemonic = "broom emerge hover abuse drink rookie silent jewel urge trap worth churn logic confirm absurd trigger save mobile leg unfold stomach harsh foil friend"
assert_equals(secret, index, secret_fingerprint, mnemonic_fingerprint, mnemonic)

