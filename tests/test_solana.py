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
"""This module contains the tests of the ethereum module."""

import logging
import base58

import time
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
    Keypair
)
from solana.transaction import Transaction
from nacl.signing import VerifyKey


from aea.common import JSONLike
from aea.crypto.helpers import DecryptError, KeyIsIncorrect

from tests.conftest import MAX_FLAKY_RERUNS, ROOT_DIR, AIRDROP_AMOUNT


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_wealth(caplog, solana_private_key_file):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        solana_faucet_api = SolanaFaucetApi()
        solana_api = SolanaApi()
        sc = SolanaCrypto(solana_private_key_file)

        transaction_digest = solana_faucet_api.get_wealth(
            sc.address, AIRDROP_AMOUNT)

        assert transaction_digest is not None

        transaction_receipt, is_settled = _wait_get_receipt(
            solana_api, transaction_digest
        )
        assert is_settled == True


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_wealth_default(caplog, solana_private_key_file):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        solana_faucet_api = SolanaFaucetApi()
        sc = SolanaCrypto(solana_private_key_file)

        tx_signature = solana_faucet_api.get_wealth(
            sc.address)

        assert tx_signature is not None


def test_creation(solana_private_key_file):
    """Test the creation of the crypto_objects."""
    assert SolanaCrypto(), "Managed to initialise the solana_keypair"
    assert SolanaCrypto(
        solana_private_key_file
    ), "Managed to load the sol private key"


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


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_load_contract_interface_from_program_id():
    """Test that you can load contract interface from onchain idl store."""
    solana_api = SolanaApi()
    contract_interface = solana_api.load_contract_interface(
        program_address="ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD", rpc_api="https://api.mainnet-beta.solana.com")

    assert "name" in contract_interface['idl'], "idl has a name"


def _wait_get_receipt(
    solana_api: SolanaApi, transaction_digest: str
) -> Tuple[Optional[JSONLike], bool]:
    transaction_receipt = None
    not_settled = True
    elapsed_time = 0
    time_to_wait = 40
    sleep_time = 1
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

    assert (
        isinstance(transfer_transaction, Transaction)
    ), "Incorrect transfer_transaction constructed."

    nonce = solana_api.generate_tx_nonce()

    if tx_params['unfunded_account']:
        signers = [account2]
    else:
        signers = []

    signed_transaction = account1.sign_transaction(
        transfer_transaction, nonce, signers
    )

    assert (
        isinstance(signed_transaction, Transaction)
    ), "Incorrect signed_transaction constructed."

    transaction_digest = solana_api.send_signed_transaction(signed_transaction)
    assert transaction_digest is not None, "Failed to submit transfer transaction!"

    transaction_receipt, is_settled = _wait_get_receipt(
        solana_api, transaction_digest
    )

    assert transaction_receipt is not None, "Failed to retrieve transaction receipt."

    return transaction_digest, transaction_receipt, is_settled


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_unfunded_transfer_transaction(solana_private_key_file):
    """Test the construction, signing and submitting of a transfer transaction."""
    account1 = SolanaCrypto(private_key_path=solana_private_key_file)
    account2 = SolanaCrypto()
    solana_api = SolanaApi()
    balance1 = solana_api.get_balance(account1.address)
    balance2 = solana_api.get_balance(account2.address)
    AMOUNT = 1232323
    tx_params = {
        "sender_address": account1.address,
        "destination_address": account2.address,
        "amount": AMOUNT,
        "unfunded_account": True,
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


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_funded_transfer_transaction(solana_private_key_file):
    """Test the construction, signing and submitting of a transfer transaction."""
    account1 = SolanaCrypto(private_key_path=solana_private_key_file)
    account2 = SolanaCrypto()

    solana_api = SolanaApi()
    solana_faucet_api = SolanaFaucetApi()

    transaction_digest = solana_faucet_api.get_wealth(
        account2.public_key, AIRDROP_AMOUNT)

    transaction_receipt, is_settled = _wait_get_receipt(
        solana_api, transaction_digest
    )

    balance1 = solana_api.get_balance(account1.public_key)

    balance2 = solana_api.get_balance(account2.public_key)
    counter = 0
    flag = True
    while flag == True and balance2 == 0:
        balance2 = solana_api.get_balance(account2.public_key)
        if balance2 != 0:
            flag = False
        counter += 1
        if counter > 10:
            flag = False
        time.sleep(2)

    AMOUNT = 2222
    tx_params = {
        "sender_address": account1.public_key,
        "destination_address": account2.public_key,
        "amount": AMOUNT,
        "unfunded_account": False,
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

    balance3 = solana_api.get_balance(account2.public_key)

    assert AMOUNT+(AIRDROP_AMOUNT *
                   LAMPORTS_PER_SOL) == balance3, "Should be the same balance"


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_sol_balance(caplog, solana_private_key_file):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        # solana_faucet_api = SolanaFaucetApi()
        sc = SolanaCrypto(private_key_path=solana_private_key_file)
        sa = SolanaApi()

        balance = sa.get_balance(sc.address)
        assert isinstance(balance, int)


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_state_from_address(solana_private_key_file):
    """Test the get_address_from_public_key method"""
    account1 = SolanaCrypto(private_key_path=solana_private_key_file)

    solana_api = SolanaApi()
    account_state = solana_api.get_state(account1.address)

    assert ("lamport" and "data" and "owner" and "rentEpoch") in account_state, "State not in correct format"


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_tx(caplog, solana_private_key_file):
    """Test get tx from signature"""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        solana_faucet_api = SolanaFaucetApi()
        sc = SolanaCrypto(private_key_path=solana_private_key_file)
        solana_api = SolanaApi()
        tx_signature = solana_faucet_api.get_wealth(
            sc.public_key, AIRDROP_AMOUNT)

        tx, settled = _wait_get_receipt(solana_api, tx_signature)
        assert settled is True
        contract_addresses = solana_api.get_contract_address(tx)
        assert contract_addresses[0] == '11111111111111111111111111111111'


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
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
    sa = SolanaApi()
    result = sa.load_contract_interface(
        idl_file_path=idl_path, bytecode_path=bytecode_path)
    pid = "ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD"
    instance = SolanaApi.get_contract_instance(SolanaApi,
                                               contract_interface=result, contract_address=pid)

    assert hasattr(instance['program'], 'coder')


def test_get_transaction_transfer_logs(solana_private_key_file):
    """Test SolanaApi.get_transaction_transfer_logs."""
    faucet = SolanaFaucetApi()
    solana_api = SolanaApi()

    account1 = SolanaCrypto(solana_private_key_file)

    tx = faucet.get_wealth(account1.address, 2)
    assert tx is not None, "Generate wealth failed"
    transaction_receipt, is_settled = _wait_get_receipt(solana_api, tx)
    assert is_settled is True

    account2 = SolanaCrypto()

    balance1 = solana_api.get_balance(account1.public_key)
    balance2 = solana_api.get_balance(account2.public_key)

    AMOUNT = 1232323
    tx_params = {
        "sender_address": account1.public_key,
        "destination_address": account2.public_key,
        "amount": AMOUNT,
        "unfunded_account": True,
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

    logs = solana_api.get_transaction_transfer_logs(transaction_digest)
    assert "preBalances" in logs
    assert "postBalances" in logs


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_deploy_program():
    """Test the deploy contract method."""

    idl_path = Path(ROOT_DIR, "tests", "data",
                    "tic-tac-toe", "target", "idl", "tic_tac_toe.json")
    bytecode_path = Path(ROOT_DIR, "tests", "data",
                         "tic-tac-toe", "target", "deploy", "tic_tac_toe.so")
    program_keypair_path = Path(
        ROOT_DIR, "tests", "data", "program_solana_private_key.txt")
    payer_keypair_path = Path(
        ROOT_DIR, "tests", "data", "solana_private_key.txt")

    sa = SolanaApi()

    program = SolanaCrypto(str(program_keypair_path))
    payer = SolanaCrypto(str(payer_keypair_path))
    # program = SolanaCrypto()
    # payer = SolanaCrypto()

    interface = sa.load_contract_interface(
        idl_file_path=idl_path, bytecode_path=bytecode_path, program_keypair=program)

    init = True
    if init:
        program.dump(str(program_keypair_path))
        payer.dump(str(payer_keypair_path))

        faucet = SolanaFaucetApi()

        tx = faucet.get_wealth(payer.address, 2)
        assert tx is not None, "Generate wealth failed"
        transaction_receipt, is_settled = _wait_get_receipt(sa, tx)
        assert is_settled is True

        balance = sa.get_balance(payer.address)
        assert balance >= 2 * LAMPORTS_PER_SOL
        print("Payer Balance: " + str(balance/LAMPORTS_PER_SOL) + " SOL")

    result = sa.get_deploy_transaction(interface, payer)
    assert result is not None, "Should not be none"


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_program_method_call():
    """Test the deploy contract method."""

    idl_path = Path(ROOT_DIR, "tests", "data",
                    "tic-tac-toe", "target", "idl", "tic_tac_toe.json")
    bytecode_path = Path(ROOT_DIR, "tests", "data",
                         "tic-tac-toe", "target", "deploy", "tic_tac_toe.so")
    program_keypair_path = Path(
        ROOT_DIR, "tests", "data", "program_solana_private_key.txt")
    payer_keypair_path = Path(
        ROOT_DIR, "tests", "data", "solana_private_key.txt")

    sa = SolanaApi()

    program = SolanaCrypto(str(program_keypair_path))
    payer = SolanaCrypto(str(payer_keypair_path))
    # program = SolanaCrypto()
    # payer = SolanaCrypto()

    interface = sa.load_contract_interface(
        idl_file_path=idl_path, bytecode_path=bytecode_path, program_keypair=program)

    init = True
    if init:
        program.dump(str(program_keypair_path))
        payer.dump(str(payer_keypair_path))

        faucet = SolanaFaucetApi()

        tx = faucet.get_wealth(payer.address, 2)
        assert tx is not None, "Generate wealth failed"
        transaction_receipt, is_settled = _wait_get_receipt(sa, tx)
        assert is_settled is True

        balance = sa.get_balance(payer.address)
        assert balance >= 2 * LAMPORTS_PER_SOL
        print("Payer Balance: " + str(balance/LAMPORTS_PER_SOL) + " SOL")
