# Copyright (c) 2016 Ofek Lev
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Transactions:
VERSION_1 = 0x01.to_bytes(4, byteorder='little')
MARKER = b'\x00'
FLAG = b'\x01'
SEQUENCE = 0xffffffff.to_bytes(4, byteorder='little')
LOCK_TIME = 0x00.to_bytes(4, byteorder='little')
HASH_TYPE = 0x61.to_bytes(4, byteorder='little')

# Scripts:
OP_0 = b'\x00'
OP_CHECKLOCKTIMEVERIFY = b'\xb1'
OP_CHECKSIG = b'\xac'
OP_DUP = b'v'
OP_EQUALVERIFY = b'\x88'
OP_HASH160 = b'\xa9'
OP_PUSH_20 = b'\x14'
OP_PUSH_32 = b'\x20'
OP_RETURN = b'\x6a'
OP_EQUAL = b'\x87'

MESSAGE_LIMIT = 40

# Address formats:
MAIN_PUBKEY_HASH = b'\x1a'
MAIN_SCRIPT_HASH = b'\x33'

# Keys:
MAIN_PRIVATE_KEY = b'\x80'
MAIN_BIP32_PUBKEY = b'\x04\x88\xb2\x1e'
MAIN_BIP32_PRIVKEY = b'\x04\x88\xad\xe4'
PUBLIC_KEY_UNCOMPRESSED = b'\x04'
PUBLIC_KEY_COMPRESSED_EVEN_Y = b'\x02'
PUBLIC_KEY_COMPRESSED_ODD_Y = b'\x03'
PRIVATE_KEY_COMPRESSED_PUBKEY = b'\x01'
