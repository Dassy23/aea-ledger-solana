# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021-2022 Valory AG
#   Copyright 2018-2019 Fetch.AI Limited
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------
"""This module contains the tests of the solana module."""

import logging
import time
import json
from pathlib import Path
from typing import Dict, Generator, Optional, Tuple, Union, cast
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest
from aea_ledger_solana import (
    SolanaApi,
    SolanaCrypto,
    SolanaFaucetApi,
    LAMPORTS_PER_SOL,
    PublicKey,
    sTransaction,
    Transaction,
    solana
)

from nacl.signing import VerifyKey


from aea.common import JSONLike
from aea.crypto.helpers import DecryptError, KeyIsIncorrect

from tests.conftest import MAX_FLAKY_RERUNS, ROOT_DIR, AIRDROP_AMOUNT

## testing keys ##
program_keypair_path = Path(
    ROOT_DIR, "tests", "data", "solana_private_key_program.txt")
payer_keypair_path = Path(
    ROOT_DIR, "tests", "data", "solana_private_key1.txt")
player1_keypair_path = Path(
    ROOT_DIR, "tests", "data", "solana_private_key1.txt")
player2_keypair_path = Path(
    ROOT_DIR, "tests", "data", "solana_private_key2.txt")

## helper functions ##


def retry_airdrop_if_result_none(faucet, address, amount=None):
    cnt = 0
    tx = None
    while tx is None and cnt < 10:
        tx = faucet.get_wealth(address, amount)
        cnt += 1
        time.sleep(2)
    return tx


def _generate_wealth_if_needed(api, address, amount=None, min_amount=None) -> Union[str, None]:

    balance = api.get_balance(address)

    min_balance = min_amount if min_amount is not None else 1000000000
    if balance >= min_balance:
        return "not required"
    else:
        faucet = SolanaFaucetApi()
        cnt = 0
        transaction_digest = None
        while transaction_digest is None and cnt < 10:
            transaction_digest = faucet.get_wealth(
                address=address, amount=amount)
            cnt += 1
            time.sleep(4)

        if transaction_digest is None:
            return "failed"
        else:
            transaction_receipt, is_settled = _wait_get_receipt(
                api, transaction_digest)
            if is_settled is True:
                return "success"
            else:
                return "failed"


def _wait_get_receipt(
    solana_api: SolanaApi, transaction_digest: str
) -> Tuple[Optional[JSONLike], bool]:
    transaction_receipt = None
    not_settled = True
    elapsed_time = 0
    time_to_wait = 40
    sleep_time = 0.25
    while not_settled and elapsed_time < time_to_wait:
        elapsed_time += sleep_time
        time.sleep(sleep_time)
        transaction_receipt = solana_api.get_transaction_receipt(
            transaction_digest)
        if transaction_receipt is None:
            continue
        is_settled = solana_api.is_transaction_settled(transaction_receipt)
        not_settled = not is_settled

    return transaction_receipt, not not_settled


def _construct_and_settle_tx(
    solana_api: SolanaApi,
    account1: SolanaCrypto,
    account2: SolanaCrypto,
    tx_params: dict,
) -> Tuple[str, JSONLike, bool]:
    """Construct and settle a transaction."""
    transfer_transaction = solana_api.get_transfer_transaction(**tx_params)
    # add nonce
    transfer_transaction = solana_api.add_nonce(transfer_transaction)

    signed_transaction = account1.sign_transaction(
        transfer_transaction
    )

    transaction_digest = solana_api.send_signed_transaction(signed_transaction)
    assert transaction_digest is not None, "Failed to submit transfer transaction!"

    transaction_receipt, is_settled = _wait_get_receipt(
        solana_api, transaction_digest
    )

    assert transaction_receipt is not None, "Failed to retrieve transaction receipt."

    return transaction_digest, transaction_receipt, is_settled

## tests ##


@ pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@ pytest.mark.integration
@ pytest.mark.ledger
def test_get_wealth(caplog, solana_private_key_file):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        solana_api = SolanaApi()
        solana_crypto = SolanaCrypto(solana_private_key_file)
        resp = _generate_wealth_if_needed(
            solana_api, solana_crypto.address, AIRDROP_AMOUNT)
        assert resp != "failed", "Failed to generate wealth"


@ pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@ pytest.mark.integration
@ pytest.mark.ledger
def test_state_from_address(solana_private_key_file):
    """Test the get_address_from_public_key method"""
    solana_api = SolanaApi()

    account_state = solana_api.get_state("11111111111111111111111111111111")

    assert account_state is not None, "State not in correct format"


# @ pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
# @ pytest.mark.integration
# @ pytest.mark.ledger
# def test_program_accounts_state_from_account(solana_private_key_file):
#     """Test the get_address_from_public_key method"""
#     solana_api = SolanaApi()

#     filters = {
#         "offset": 0,
#         "bytes": b"\x9fu_\xe3\xef\x97:\xec"
#     }

#     account_state = solana_api.get_program_accounts_state(
#         address="dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH", filters=filters)

#     assert account_state is not None, "State not in correct format"


def test_creation(solana_private_key_file):
    """Test the creation of the crypto_objects."""
    assert SolanaCrypto(), "Managed to initialise the solana_keypair"
    assert SolanaCrypto(
        solana_private_key_file
    ), "Managed to load the sol private key"


def test_decode_lookup_table():
    """Test the creation of the crypto_objects."""
    data = b'\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xb4P\xbe\n\x00\x00\x00\x00\n\x01\xe8\xfe\xc3Q-}y\x10-\xa1\xc3W\xe7\xfc\x05\xa7\xb2\x00t\xa3\xaf\xd3\xc5~\x83\x1a*\x0btO\xb4~\x00\x00o\x00}\xc4\x17\xae\xf2\x06\xa6\x94A\xea\xdc\xb6\x99\xb8\xca\xaaJ\xf9\x03R\xadp\x90\xcf\xbe\xa9\xf8\x1f\xa4k\x15\xea\xf5\x8b\xc0\x96>\xd7\xc7X\xd8k+\x9a\xb3ev\t\xc8H\x1e\xe9\x99\xb7\x1f\xed\xc9\xfdK\x81Y\xe0\x0f\xf1_\x05oW\xa9\x18\xdcab\x8b\xe0\xb7\xa4,\x94hTO\xa1\xd5\xd74\xe9|)+\x91\xbc\x0b\x92_\x15\xa8S\x8e\xeb\xa8\xc3}T\xd7\x9c\x15u\x9e\x93SB\xfe\x01w\xd6\xbf\xfaC86\\\xc6\xda\xe2\x89T_\xa3\x0e\xa3\xbc?<)f\xda\x8bl=\xfe\xf8\xd3\xab}\xa5|\xa0#*T\xe4\xa0&O\xff\xc3\xc2+\xd6T*h\xe4\x85a/V\x10\xb7\x13\xd7\x83{\x98\x96=x\xb2[%ylg\xd6y\xfc\x05\x0f6\xef\r\x8bo\xda,\xeb\xa4\x1d\xa1]@\x95\xd1\xda9*\r/\x8e\xd0\xc6\xc7\xbc\x0fL\xfa\xc8\xc2\x80\xb5m\xe6-\xf6\xc8\xb4\xa8_\xe1\xa6}\xb4M\xc1-\xe5\xdb3\x0fz\xc6kr\xdce\x8a\xfe\xdf\x0fJA[C\xffaI\x1a\x93\x11\x12\xdd\xf1\xbd\x81G\xcd\x1bd\x13u\xf7\x9fX%\x12mfT\x80\x87F4\xfd\n\xce\x03\xaeM\xb2\x9e\xd4\xae3\xd3#V\x88\x95\xaa\x003~e\x8e4\x8b7P\x9fSr\xaeQ\xf0\xaf\x00\xd5\x14\xea\xd5U\x91ZH\x1d\xd8\xeb^)y\xf8\x19h\xec\xce\xe7\xa3MR\x131d\xbc#v\x9d)\xde\x97r\xb0!!|\xa3\xfeh\x92*\x19\xaa\xf9\x90\x10\x9c\xb9\xd8N\x9a\xd0\x04\xb4\xd2\x02Z\xd6\xf5)1D\x19'
    solana_api = SolanaApi()
    table = solana_api.decode_lookup_table(data)
    assert table is not None, "Decoded lookup table"


def test_derive_address():
    """Test the get_address_from_public_key method"""
    account = SolanaCrypto()
    address = SolanaApi.get_address_from_public_key(account.public_key)
    assert account.address == address, "Address derivation incorrect"


def test_get_hash():
    """Test the get hash functionality."""
    expected_hash = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    hash_ = SolanaApi.get_hash(message=b"hello")
    assert expected_hash == hash_


def test_is_address_valid():
    """Test the get hash functionality."""
    wallet = SolanaCrypto()
    sa = SolanaApi()
    assert sa.is_valid_address(wallet.address) == True

    assert sa.is_valid_address("123IamNotReal") == False


def test_sign_message():
    """Test message sign functionality."""
    wallet = SolanaCrypto()
    wallet2 = SolanaCrypto()
    msg = bytes("hello", 'utf8')
    msg2 = bytes("hellooo", 'utf8')

    sig = wallet.sign_message(msg)

    try:
        result = VerifyKey(
            bytes(wallet.public_key)
        ).verify(
            smessage=msg2,
            signature=bytes(sig.to_bytes_array())
        )
    except Exception as e:
        assert e.args[0] == 'Signature was forged or corrupt'

    try:
        result = VerifyKey(
            bytes(wallet2.public_key)
        ).verify(
            smessage=msg,
            signature=bytes(sig.to_bytes_array())
        )
    except Exception as e:
        assert e.args[0] == 'Signature was forged or corrupt'

    result = VerifyKey(
        bytes(wallet.public_key)

    ).verify(
        smessage=msg,
        signature=bytes(sig.to_bytes_array())
    )

    assert result == msg, "Failed to sign message"


@ pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@ pytest.mark.integration
@ pytest.mark.ledger
def test_load_contract_interface_from_program_id():
    """Test that you can load contract interface from onchain idl store."""
    solana_api = SolanaApi()
    idl_path = Path(ROOT_DIR, "tests", "data",
                    "tic-tac-toe", "target", "idl", "tic_tac_toe.json")
    contract_interface = solana_api.load_contract_interface(
        file_path=idl_path)

    assert "name" in contract_interface['idl'], "idl has a name"


@ pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@ pytest.mark.integration
@ pytest.mark.ledger
def test_unfunded_transfer_transaction(solana_private_key_file):
    """Test the construction, signing and submitting of a transfer transaction."""
    account1 = SolanaCrypto(payer_keypair_path)
    account2 = SolanaCrypto()
    solana_api = SolanaApi()
    resp = _generate_wealth_if_needed(solana_api, account1.address)
    assert resp != "failed", "Failed to generate wealth"

    balance1 = solana_api.get_balance(account1.address)
    balance2 = solana_api.get_balance(account2.address)
    AMOUNT = 1232323
    tx_params = {
        "sender_address": account1.address,
        "destination_address": account2.address,
        "amount": AMOUNT,
    }

    transaction_digest, transaction_receipt, is_settled = _construct_and_settle_tx(
        solana_api,
        account1,
        account2,
        tx_params,

    )
    assert is_settled, "Failed to verify tx!"

    tx = solana_api.get_transaction(transaction_digest)

    assert tx['blockTime'] == transaction_receipt['blockTime'], "Should be same"

    balance3 = solana_api.get_balance(account2.address)

    assert AMOUNT == balance3, "Should be the same balance"


@ pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@ pytest.mark.integration
@ pytest.mark.ledger
def test_funded_transfer_transaction(solana_private_key_file):
    """Test the construction, signing and submitting of a transfer transaction."""
    account1 = SolanaCrypto(payer_keypair_path)
    account2 = SolanaCrypto(player2_keypair_path)

    solana_api = SolanaApi()
    solana_faucet_api = SolanaFaucetApi()
    resp = _generate_wealth_if_needed(solana_api, account1.address)
    assert resp != "failed", "Failed to generate wealth"
    resp = _generate_wealth_if_needed(solana_api, account2.address)
    assert resp != "failed", "Failed to generate wealth"

    balance1 = solana_api.get_balance(account1.public_key)
    balance2 = solana_api.get_balance(account2.public_key)
    counter = 0
    flag = True
    while flag is True and balance2 == 0:
        balance2 = solana_api.get_balance(account2.public_key)
        if balance2 != 0:
            flag = False
        counter += 1
        if counter > 10:
            flag = False
        time.sleep(2)

    amount = 2222
    tx_params = {
        "sender_address": account1.public_key,
        "destination_address": account2.public_key,
        "amount": amount,
    }

    transaction_digest, transaction_receipt, is_settled = _construct_and_settle_tx(
        solana_api,
        account1,
        account2,
        tx_params,
    )
    assert is_settled, "Failed to verify tx!"

    transaction = solana_api.get_transaction(transaction_digest)

    assert transaction['blockTime'] == transaction_receipt['blockTime'], "Should be same"


@ pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@ pytest.mark.integration
@ pytest.mark.ledger
def test_get_sol_balance(caplog):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        # solana_faucet_api = SolanaFaucetApi()
        solana_crypto = SolanaCrypto(payer_keypair_path)
        solana_api = SolanaApi()

        balance = solana_api.get_balance(solana_crypto.address)
        assert isinstance(balance, int)


@ pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@ pytest.mark.integration
@ pytest.mark.ledger
def test_get_tx(caplog, solana_private_key_file):
    """Test get tx from signature"""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        solana_faucet_api = SolanaFaucetApi()
        solana_crypto = SolanaCrypto(private_key_path=solana_private_key_file)
        solana_api = SolanaApi()

        retries = 0
        tx_signature = None
        while retries < MAX_FLAKY_RERUNS:
            tx_signature = solana_faucet_api.get_wealth(
                address=solana_crypto.public_key, amount=AIRDROP_AMOUNT)
            if tx_signature is None:
                retries += 1
                time.sleep(2)
            else:
                break

        assert tx_signature is not None
        tx, settled = _wait_get_receipt(solana_api, tx_signature)
        assert settled is True
        contract_addresses = solana_api.get_contract_address(tx)
        assert contract_addresses[0] == '11111111111111111111111111111111'


@ pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@ pytest.mark.integration
@ pytest.mark.ledger
def test_encrypt_decrypt_privatekey(caplog, solana_private_key_file):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        sc = SolanaCrypto(private_key_path=solana_private_key_file)
        privKey = sc.private_key

        encrypted = sc.encrypt("test123456788")

        decrypted = sc.decrypt(encrypted, "test123456788")
        assert privKey == decrypted, "Private keys match"


def test_load_contract_interface():
    """Test the load_contract_interface method."""
    path = Path(ROOT_DIR, "tests", "data",
                "dummy_contract", "build", "idl.json")
    result = SolanaApi.load_contract_interface(path)

    assert "name" in result['idl']


def test_load_contract_instance():
    """Test the load_contract_interface method."""
    idl_path = Path(ROOT_DIR, "tests", "data",
                    "spl-token-faucet", "target", "idl", "spl_token_faucet.json")
    bytecode_path = Path(ROOT_DIR, "tests", "data",
                         "spl-token-faucet", "target", "deploy", "spl_token_faucet.so")
    solana_api = SolanaApi()
    result = solana_api.load_contract_interface(
        file_path=idl_path, bytecode_path=bytecode_path)
    pid = "ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD"
    instance = SolanaApi.get_contract_instance(SolanaApi,
                                               contract_interface=result, contract_address=pid)

    assert hasattr(instance['program'], 'coder')


def test_get_transaction_transfer_logs():
    """Test SolanaApi.get_transaction_transfer_logs."""
    solana_api = SolanaApi()

    account1 = SolanaCrypto(payer_keypair_path)

    resp = _generate_wealth_if_needed(solana_api, account1.address)
    assert resp != "failed", "Failed to generate wealth"

    account2 = SolanaCrypto()

    # balance1 = solana_api.get_balance(account1.public_key)
    # balance2 = solana_api.get_balance(account2.public_key)

    amount = 1232323
    tx_params = {
        "sender_address": account1.public_key,
        "destination_address": account2.public_key,
        "amount": amount,
        "unfunded_account": True,
    }

    transaction_digest, transaction_receipt, is_settled = _construct_and_settle_tx(
        solana_api,
        account1,
        account2,
        tx_params,

    )
    assert is_settled, "Failed to verify tx!"

    transaction = solana_api.get_transaction(transaction_digest)

    assert transaction['blockTime'] == transaction_receipt['blockTime'], "Should be same"

    logs = solana_api.get_transaction_transfer_logs(transaction_digest)
    assert "preBalances" in logs
    assert "postBalances" in logs


@ pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@ pytest.mark.integration
@ pytest.mark.ledger
def test_contract_method_call():
    """Test the deploy contract method."""

    start = time.time()
    idl_path = Path(ROOT_DIR, "tests", "data",
                    "tic-tac-toe", "target", "idl", "tic_tac_toe.json")
    bytecode_path = Path(ROOT_DIR, "tests", "data",
                         "tic-tac-toe", "target", "deploy", "tic_tac_toe.so")
    program_keypair_path = Path(
        ROOT_DIR, "tests", "data", "solana_private_key_program.txt")
    payer_keypair_path = Path(
        ROOT_DIR, "tests", "data", "solana_private_key0.txt")

    solana_api = SolanaApi()
    payer = SolanaCrypto(str(payer_keypair_path))
    program_kp = SolanaCrypto(str(program_keypair_path))

    interface = solana_api.load_contract_interface(
        file_path=idl_path, bytecode_path=bytecode_path, program_keypair=program_kp)

    instance = solana_api.get_contract_instance(
        contract_interface=interface, contract_address=program_kp.address)

    program = instance['program']

    player1 = payer
    # player2 = SolanaCrypto()
    player2 = SolanaCrypto("./tests/data/solana_private_key2.txt")
    game = SolanaCrypto()

    # print("game: " + str(game.address))
    # print("p1 - payer: " + str(player1.address))
    # print("p2: " + str(player2.address))

    resp = _generate_wealth_if_needed(solana_api, payer.address)
    assert resp != "failed", "Failed to generate wealth"

    resp = _generate_wealth_if_needed(solana_api, player2.address)
    assert resp != "failed", "Failed to generate wealth"

    # setup game
    program.provider.wallet = payer.entity

    accounts = {
        "game": game.public_key,
        "player_one": payer.public_key,
        "system_program": PublicKey("11111111111111111111111111111111")}

    trasaction = solana_api.build_transaction(program, "setup_game", method_args={
        "data": (player2.public_key,),
        "accounts": accounts,
    }, tx_args=None)

    trasaction = solana_api.add_nonce(trasaction)

    signed_transaction = game.sign_transaction(
        trasaction, [payer])

    transaction_digest = solana_api.send_signed_transaction(
        signed_transaction)
    assert transaction_digest is not None
    transaction_receipt, is_settled = _wait_get_receipt(
        solana_api, transaction_digest)
    assert is_settled is True
    state = solana_api.get_state(game.public_key)
    decoded_state = program.coder.accounts.decode(state.data)

    player1 = payer
    column = 0
    # print(time.time() - start)
    # time.sleep(2)

    # game loop
    start = time.time()
    while decoded_state.state.index == 0:

        active_player = player2 if decoded_state.turn % 2 == 0 else player1
        row = 0 if decoded_state.turn % 2 == 0 else 1
        accounts = {
            "game": game.public_key,
            "player": active_player.public_key
        }

        tile = program.type['Tile'](row=row, column=column)

        tx1 = solana_api.build_transaction(program, "play",
                                           method_args={
                                               "data": (tile,),
                                               "accounts": accounts,


                                           },
                                           tx_args={"type": "instruction"})
        #    tx_args=None)

        tx1 = solana_api.add_nonce(tx1)

        signed_transaction = active_player.sign_transaction(
            tx1, )

        transaction_digest = solana_api.send_signed_transaction(
            signed_transaction)
        assert transaction_digest is not None
        transaction_receipt, is_settled = _wait_get_receipt(
            solana_api, transaction_digest)
        assert is_settled is True
        state = solana_api.get_state(game.public_key)
        decoded_state = program.coder.accounts.decode(state.data)

        if row == 0:
            column += 1

    # print(time.time() - start)
    assert decoded_state.state.winner == player1.public_key
