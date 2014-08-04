#!/usr/bin/env python
# -*- coding: utf-8 -*-

from src.models import Transaction, Input, Output
from src.utils import *

config.TESTNET = True

sig_hash_type = SIGHASH_ALL

input = Input()
input.tx_id = 'f1c91838e62fd3914b4f5a6aa8ed7905652263491e334ceceff946810987ff8c'.decode('hex')[::-1] # Must be little-endian
input.output_index = 0
input_private_key = wif_to_private_key('cToipAmMoB1EkfTXNbmu2JH4pvG7w6w2EmP7H48HfUommgov9NeQ')
input_public_key = private_key_to_public_key(input_private_key)
input_public_key_hash = public_key_to_public_key_hash(input_public_key)
input.script_sig = build_p2pkh_script_pub_key(input_public_key_hash)

output_public_key_hash = address_to_public_key_hash('msdXvzp45CABWk4yG3oTuYXgZ6VpZRaMPY')
output_script_pub_key = build_p2pkh_script_pub_key(output_public_key_hash)
output = Output(int(5.99e8), output_script_pub_key)

tx = Transaction(inputs=[input], outputs=[output])

sig = input.sign_transaction(tx, input_private_key, sig_hash_type)
input.script_sig = build_p2pkh_script_sig(sig, input_public_key)

print 'Transaction hash:', tx.hash()[::-1].encode('hex')
print 'Raw transaction:'
print tx.data().encode('hex')
