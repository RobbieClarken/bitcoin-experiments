# -*- coding: utf-8 -*-

import hashlib
from hashlib import sha256
import ecdsa
from ecdsa import SECP256k1
from math import log, ceil
import config

BASE58_CHARACTERS = ('123456789ABCDEFGHJKLMNPQRSTUVWXYZ'
                     'abcdefghijkmnopqrstuvwxyz')

OP_DUP = '\x76'
OP_HASH160 = '\xa9'
OP_EQUALVERIFY = '\x88'
OP_CHECKSIG = '\xac'
OP_NOP = '\x61'

SIGHASH_ALL = 0x00000001
SIGHASH_NONE = 0x00000002
SIGHASH_SINGLE = 0x00000003
SIGHASH_ANYONECANPAY = 0x00000080


def int_to_bytes(i, size=None, little_endian=True):

    if size is None:
        size = int(ceil(log(i, 2) / 8))

    n = 2 * size
    s = format(i, 'x').zfill(n)
    if len(s) > n:
        raise Exception('{} cannot be represented '
                        'with {} bytes'.format(i, size))
    bytes = s.decode('hex')
    if little_endian:
        bytes = bytes[::-1]

    return bytes


def bytes_to_int(bytes, little_endian=True):
    if little_endian:
        bytes = bytes[::-1]
    s = bytes.encode('hex')
    return int(s, 16)


def int_to_var_int_bytes(i):

    if i < 0xfd:
        prefix = ''
        size = 1
    elif i <= 0xffff:
        prefix = '\xfd'
        size = 2
    elif i <= 0xffffffff:
        prefix = '\xfe'
        size = 4
    else:
        prefix = '\xff'
        size = 8

    return prefix + int_to_bytes(i, size)


def var_int_bytes_to_int(s):

    length = var_int_length(s)

    if length == 1:
        s = s[0]
    else:
        s = s[1:length]

    return bytes_to_int(s)


def var_int_length(s):
    lookup = {'\xfd': 3, '\xfe': 5, '\xff': 9}
    return lookup.get(s[0]) or 1


def base58_encode(data):

    x = bytes_to_int(data, little_endian=False)
    s = ''
    while x:
        x, remainder = divmod(x, 58)
        s += BASE58_CHARACTERS[remainder]

    leading_zeros = len(data) - len(data.lstrip('\x00'))
    s += '1' * leading_zeros

    return s[::-1]


def base58_decode(s):

    val = 0
    for i, c in enumerate(reversed(s)):
        val += 58 ** i * BASE58_CHARACTERS.index(c)
    bytes = int_to_bytes(val, little_endian=False)
    leading_zeros = len(s) - len(s.lstrip('1'))
    bytes = '\x00' * leading_zeros + bytes

    return bytes


def private_key_to_wif(private_key, compressed=True):
    prefix = '\xef' if config.TESTNET else '\x80'
    ext_priv_key = prefix + private_key
    if compressed:
        ext_priv_key += '\x01'
    hashed_priv_key = sha256(sha256(ext_priv_key).digest()).digest()
    checksum = hashed_priv_key[0:4]
    wif = base58_encode(ext_priv_key + checksum)
    return wif


def wif_to_private_key(wif):

    if config.TESTNET:
        expected_prefix = '\xef'
        compressed = wif[0] != '9'
    else:
        expected_prefix = '\x80'
        compressed = wif[0] != '5'

    byte_str = base58_decode(wif)
    ext_priv_key, checksum = byte_str[:-4], byte_str[-4:]
    second_checksum = sha256(sha256(ext_priv_key).digest()).digest()[:4]

    if checksum != second_checksum:
        raise ValueError('Invalid checksum')

    prefix, private_key = ext_priv_key[:1], ext_priv_key[1:]

    if prefix != expected_prefix:
        raise ValueError('Unexpected prefix')

    if compressed:
        if private_key[-1] != '\x01':
            raise ValueError('Unexpected byte at end of private key')
        private_key = private_key[:-1]

    return private_key


def private_key_to_public_key(private_key, compressed=True):

    signing_key = ecdsa.SigningKey.from_string(private_key,
                                               curve=SECP256k1)
    verifying_key = signing_key.verifying_key
    public_key = '\x04' + verifying_key.to_string()
    if compressed:
        public_key = compress_public_key(public_key)

    return public_key


def uncompress_public_key(compressed_public_key):

    sign = compressed_public_key[0]
    x = bytes_to_int(compressed_public_key[1:], little_endian=False)

    a = x ** 3 + 7
    p = SECP256k1.curve.p()

    if jacobi(a, p) != 1:
        raise ValueError('Invalid compressed public key')

    y = pow(a, (p+1)/4, p)

    if sign == '\x02':
        y = -y % p

    public_key = ('\x04' +
                  int_to_bytes(x, 32, little_endian=False) +
                  int_to_bytes(y, 32, little_endian=False))

    return public_key


def compress_public_key(uncompressed_public_key):

    if uncompressed_public_key[0] != '\x04':
        raise ValueError('Public key must start with 04')

    if len(uncompressed_public_key) != 65:
        raise ValueError('Public key must be 65 bytes long')

    x = bytes_to_int(uncompressed_public_key[1:33], little_endian=False)
    y = bytes_to_int(uncompressed_public_key[33:], little_endian=False)

    sign = '\x03' if y & 1 else '\x02'
    public_key = sign + int_to_bytes(x, 32, little_endian=False)

    return public_key


def public_key_to_public_key_hash(public_key):

    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256(public_key).digest())
    public_key_hash = ripemd160.digest()

    return public_key_hash


def public_key_to_address(public_key):

    version_byte = '\x6f' if config.TESTNET else '\x00'
    public_key_hash = public_key_to_public_key_hash(public_key)
    ext_hash = version_byte + public_key_hash

    checksum = sha256(sha256(ext_hash).digest()).digest()[:4]
    address = base58_encode(ext_hash + checksum)

    return address


def private_key_to_address(private_key, compressed=True):
    public_key = private_key_to_public_key(private_key, compressed)
    return public_key_to_address(public_key)


def address_to_public_key_hash(address):
    public_key_hash = base58_decode(address)[:-4]
    public_key_hash = public_key_hash[1:]
    return public_key_hash


def build_script_sig(signature, hash_type, public_key):

    sig_and_hash_type = signature + int_to_bytes(hash_type, 1)
    script_sig = (int_to_bytes(len(sig_and_hash_type), 1) +
                  sig_and_hash_type +
                  int_to_bytes(len(public_key), 1) +
                  public_key)

    return script_sig


def decode_script_sig(script_sig):

    sig_len = bytes_to_int(script_sig[0]) - 1
    signature = script_sig[1:1+sig_len]
    hash_type = bytes_to_int(script_sig[1+sig_len])
    public_key_len = bytes_to_int(script_sig[1+sig_len+1])
    public_key = script_sig[1+sig_len+2:]
    assert len(public_key) == public_key_len

    return signature, hash_type, public_key


def build_p2pkh_script(public_key_hash):
    return (OP_DUP + OP_HASH160 +
            int_to_bytes(len(public_key_hash), 1) +
            public_key_hash +
            OP_EQUALVERIFY +
            OP_CHECKSIG)


def decode_p2pkh_script(script):

    assert script[0] == OP_DUP
    assert script[1] == OP_HASH160
    pkh_len = bytes_to_int(script[2])
    public_key_hash = script[3:3+pkh_len]
    assert script[pkh_len+4] == OP_EQUALVERIFY
    assert script[pkh_len+5] == OP_CHECKSIG

    return public_key_hash


def build_pubkey_script(public_key):
    return (int_to_bytes(len(public_key), 1) +
            public_key +
            OP_CHECKSIG)

def jacobi(a, n):

    """
    Algorithm described in Bach & Shallit 1996, p. 113.
    """

    if not n & 1:
        raise ValueError('n must be odd')

    a = a % n
    t = 1

    while a:
        while not a & 1:
            a = a // 2
            if n & 7 in (3, 5):
                t = -t
        a, n = n, a
        if a & 3 == 3 and n & 3 == 3:
            t = -t
        a = a % n

    return t if n == 1 else 0
