#!/usr/bin/env python
# -*- coding: utf-8 -*-

from src.models import Transaction, Input, Output
from src.utils import *

config.TESTNET = True

sig_hash_type = SIGHASH_ALL

input = Input()
input.tx_id = 'f110565c3fdbd5610947e04d55a7ce05c59f76db4a99072f6af03ac7b1ddd7b6'.decode('hex')[::-1] # Must be little-endian
input.output_index = 0
input_private_key = wif_to_private_key('cNoujZFooA1i3F7RyJHcwkebKL2QPZh8zfvehG1zZFygsduyRUBz')
input_public_key = private_key_to_public_key(input_private_key)
input_public_key_hash = public_key_to_public_key_hash(input_public_key)
input.script_sig = build_p2pkh_script(input_public_key_hash)

output_public_key_hash = address_to_public_key_hash('mx6gmXwLFVYEuWn8TyCXpJSNPpsfV7Q5kQ')
output_script_pub_key = build_p2pkh_script(output_public_key_hash)
output = Output(int(0.45e8), output_script_pub_key)

tx = Transaction(inputs=[input], outputs=[output])

hash_for_signing = tx.hash(hash_type=sig_hash_type)

input.sign_transaction(hash_for_signing, sig_hash_type, input_private_key, input_public_key)

print 'Transaction hash:', tx.hash()[::-1].encode('hex')
print 'Raw transaction:'
print tx.data().encode('hex')
