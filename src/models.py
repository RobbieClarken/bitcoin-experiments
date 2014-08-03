# -*- coding: utf-8 -*-

from utils import *


class Transaction(object):


    def __init__(self, version=1, inputs=None, outputs=None, lock_time=0):
        super(Transaction, self).__init__()
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lock_time = lock_time


    def data(self):

        return (int_to_bytes(self.version, 4) +
                int_to_var_int_bytes(len(self.inputs)) +
                ''.join(i.data() for i in self.inputs) +
                int_to_bytes(len(self.outputs), 1) +
                ''.join(o.data() for o in self.outputs) +
                int_to_bytes(self.lock_time, 4))


    def hash(self, hash_type=None):

        tx_data = self.data()

        if hash_type is not None:
            tx_data += int_to_bytes(hash_type, 4)

        return sha256(sha256(tx_data).digest()).digest()


    @classmethod
    def from_data(cls, data):

        tx = cls()
        tx.version = bytes_to_int(data[0:4])
        input_count = var_int_bytes_to_int(data[4:])
        e = 4 + var_int_length(data[4:])
        tx.inputs = []
        for i in range(input_count):
            input = Input.from_data(data[e:])
            tx.inputs.append(input)
            e += len(input.data())
        output_count = bytes_to_int(data[e])
        e += 1
        tx.outputs = []
        for i in range(output_count):
            output = Output.from_data(data[e:])
            tx.outputs.append(output)
            e += len(output.data())
        tx.lock_time = bytes_to_int(data[e:e+4])

        return tx


class Input(object):


    def __init__(self, tx_id=None, output_index=None,
                 script_sig=None, sequence='\xff\xff\xff\xff'):

        super(Input, self).__init__()
        self.tx_id = tx_id
        self.output_index = output_index
        self.script_sig = script_sig
        self.sequence = sequence


    def __repr__(self):

        repr_data = (
            self.tx_id.encode('hex'),
            self.output_index,
            self.script_sig.encode('hex'),
            self.sequence.encode('hex')
        )

        return ('Input(tx_id={0}, '
                'output_index={1}, '
                'script_sig={2}, '
                'sequence={3})').format(*repr_data)


    def sign_transaction(self, tx_hash, hash_type,
                         private_key, public_key):

        signing_key = ecdsa.SigningKey.from_string(private_key,
                                                   curve=SECP256k1)
        signature = signing_key.sign_digest(
            tx_hash,
            sigencode=ecdsa.util.sigencode_der
        )

        self.script_sig = build_script_sig(signature, hash_type,
                                           public_key)


    def data(self):

        return (self.tx_id +
                int_to_bytes(self.output_index, 4) +
                int_to_var_int_bytes(len(self.script_sig)) +
                self.script_sig +
                self.sequence)


    @classmethod
    def from_data(cls, data):

        input = cls()
        input.tx_id = data[:32]
        input.output_index = bytes_to_int(data[32:36])
        script_sig_len = var_int_bytes_to_int(data[36:])
        vi_len = var_int_length(data[36:])
        s = 36 + vi_len
        e = s + script_sig_len
        input.script_sig = data[s:e]
        s, e = e, e + 4
        input.sequence = data[s:e]

        return input


class Output(object):


    def __init__(self, value=None, script_pub_key=None):

        super(Output, self).__init__()
        self.value = value
        self.script_pub_key = script_pub_key


    def __repr__(self):

        repr_data = (self.value, self.script_pub_key.encode('hex'))

        return ('Output(value={0}, '
                'script_pub_key={1})').format(*repr_data)


    def data(self):
        return (int_to_bytes(self.value, 8) +
                int_to_var_int_bytes(len(self.script_pub_key)) +
                self.script_pub_key)


    @classmethod
    def from_data(cls, data):

        output = cls()
        output.value = bytes_to_int(data[:8])
        vi_len = var_int_length(data[8:])
        spk_len = var_int_bytes_to_int(data[8:])
        output.script_pub_key = data[8+vi_len:8+vi_len+spk_len]

        return output


class Block(object):


    MAX_TARGET = 0xFFFF0000000000000000000000000000000000000000000000000000
    POOL_MAX_TARGET = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


    @property
    def target(self):
        return decode_target_bits(self.bits)


    @property
    def difficulty(self):
        return float(self.MAX_TARGET) / self.target


    @property
    def pool_difficulty(self):
        return float(self.POOL_MAX_TARGET) / self.target


    def data(self):
        return (
            int_to_bytes(self.magic_number, 4) +
            int_to_bytes(self.block_size, 4) +
            self.header_data() +
            ''.join(tx.data() for tx in self.transactions)
        )


    def header_data(self, null_tx_count=False):
        tx_count = 0 if null_tx_count else self.tx_count
        return (
            int_to_bytes(self.version, 4) +
            self.hash_prev_block +
            self.hash_merkle_root +
            int_to_bytes(self.time, 4) +
            self.bits +
            int_to_bytes(self.nonce, 4) +
            int_to_var_int_bytes(tx_count)
        )


    def hash(self):
        data = self.header_data(null_tx_count=True)[:-1]
        return sha256(sha256(data).digest()).digest()


    @classmethod
    def from_data(cls, data):

        self = cls()

        s, e = 0, 4
        self.magic_number = bytes_to_int(data[s:e])
        s, e = e, e + 4
        self.block_size = bytes_to_int(data[s:e])

        s, e = e, e + 4
        self.version = bytes_to_int(data[s:e])
        s, e = e, e + 32
        self.hash_prev_block = data[s:e]
        s, e = e, e + 32
        self.hash_merkle_root = data[s:e]
        s, e = e, e + 4
        self.time = bytes_to_int(data[s:e])
        s, e = e, e + 4
        self.bits = data[s:e]
        s, e = e, e + 4
        self.nonce = bytes_to_int(data[s:e])

        s = e
        e = s + var_int_length(data[s:])
        self.tx_count = var_int_bytes_to_int(data[s:e])

        self.transactions = []
        for i in range(self.tx_count):
            s = e
            tx = Transaction.from_data(data[s:])
            self.transactions.append(tx)
            e += len(tx.data())

        return self
