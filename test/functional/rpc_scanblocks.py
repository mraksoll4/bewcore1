#!/usr/bin/env python3
# Copyright (c) 2021-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the scanblocks RPC call."""
from test_framework.address import address_to_scriptpubkey
from test_framework.blockfilter import (
    bip158_basic_element_hash,
    bip158_relevant_scriptpubkeys,
)
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
    getnewdestination,
)


# Ваши данные для нового генезис блока
new_genesis_spk = bytes.fromhex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
new_genesis_output_index = 0  # Индекс вывода для вашего нового генезис блока
new_genesis_blockhash = "2013e6667f33ca0c77ceb427a87ed3360ea8d16f772175d42e62e5b6422aaffc"

# Расчет false positive
new_genesis_false_positive = bip158_basic_element_hash(new_genesis_spk, new_genesis_output_index, new_genesis_blockhash)
print(new_genesis_false_positive)