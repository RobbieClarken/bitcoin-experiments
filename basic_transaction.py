#!/usr/bin/env python
# -*- coding: utf-8 -*-

from src.models import Transaction, Input, Output
from src.utils import *

config.TESTNET = True

sig_hash_type = SIGHASH_ALL

input = Input()
input.tx_id = '3840dbc5c545c776f4eee4b60b2028cc2a31c19db06327c2ac1a674fbaa38a7c'.decode('hex')
input.output_index = 0
input_private_key = wif_to_private_key('cUDPEriH7mjVKUYdZsuDHdxGiJu9nVoTXzTX4UsS8HjAbFsJp9MA')
input_public_key = private_key_to_public_key(input_private_key)
input_public_key_hash = public_key_to_public_key_hash(input_public_key)
input.script_sig = build_p2pkh_script(input_public_key_hash)

output_public_key_hash = address_to_public_key_hash('mrZfwZ77outTQhij7f2RYPDqJRbRpTpPjY')
output_script_pub_key = build_p2pkh_script(output_public_key_hash)
output = Output(int(0.47e8), output_script_pub_key)

tx = Transaction(inputs=[input], outputs=[output])

hash_for_signing = tx.hash(hash_type=sig_hash_type)

input.sign_transaction(hash_for_signing, sig_hash_type, input_private_key, input_public_key)

print 'Raw transaction:'
print tx.data().encode('hex')
