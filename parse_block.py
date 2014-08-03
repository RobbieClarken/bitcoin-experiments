#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Extracts data from the first block in a .dat file.

Usage: parse_block.py [path to .dat file]
"""

from src.models import Block
from sys import argv

MAX_BLOCK_SIZE = 1024 ** 2 # 1 MB

file_path = argv[1]
with open(file_path) as f:
    block = Block.from_data(f.read(MAX_BLOCK_SIZE))

print 'Hash:', block.hash()[::-1].encode('hex')
print 'Magic number: {:x}'.format(block.magic_number)
print 'Block size:', block.block_size
print 'Version:', block.version
print 'Hash of previous block:', block.hash_prev_block[::-1].encode('hex')
print 'Hash of merkle root:', block.hash_merkle_root[::-1].encode('hex')
print 'Time:', block.time
print 'Target: {:064x} ({})'.format(block.target, block.bits.encode('hex'))
print 'Difficulty:', block.difficulty
print 'Pool difficulty:', block.pool_difficulty
print 'Nonce:', block.nonce
print 'Number of transactions:', block.tx_count
