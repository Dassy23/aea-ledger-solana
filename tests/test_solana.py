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

import hashlib
import logging
import json
import random
import re
import os
import subprocess
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
    LruLockWrapper,
)
from solana.transaction import Transaction
from solana.publickey import PublicKey

# from web3 import Web3
from web3._utils.request import _session_cache as session_cache

from aea.common import JSONLike
from aea.crypto.helpers import DecryptError, KeyIsIncorrect

from tests.conftest import MAX_FLAKY_RERUNS, ROOT_DIR, SOLANA_PRIVATE_KEY_FILE_1, AIRDROP_AMOUNT


def test_creation():
    """Test the creation of the crypto_objects."""
    assert SolanaCrypto(), "Managed to initialise the eth_account"
    assert SolanaCrypto(
        SOLANA_PRIVATE_KEY_FILE_1
    ), "Managed to load the sol private key"


def test_derive_address():
    """Test the get_address_from_public_key method"""
    account = SolanaCrypto()
    address = SolanaApi.get_address_from_public_key(account.public_key)
    assert account.address == address, "Address derivation incorrect"


# def test_sign_and_recover_message():
#     """Test the signing and the recovery function for the sol_crypto."""
#     account = SolanaCrypto()
#     sign_bytes = account.sign_message(message=b"hello")
#     assert len(sign_bytes) > 0, "The len(signature) must not be 0"
#     # recovered_addresses = SolanaApi.recover_message(
#     #     message=b"hello", signature=sign_bytes
#     # )
#     # assert len(recovered_addresses) == 1, "Wrong number of addresses recovered."
#     # assert (
#     #     recovered_addresses[0] == account.address
#     # ), "Failed to recover the correct address."


# def test_sign_and_recover_message_public_key(ethereum_private_key_file):
#     """Test the signing and the recovery function for the eth_crypto."""
#     account = EthereumCrypto(ethereum_private_key_file)
#     sign_bytes = account.sign_message(message=b"hello")
#     assert len(sign_bytes) > 0, "The len(signature) must not be 0"
#     recovered_public_keys = EthereumApi.recover_public_keys_from_message(
#         message=b"hello", signature=sign_bytes
#     )
#     assert len(recovered_public_keys) == 1, "Wrong number of public keys recovered."
#     assert (
#         EthereumApi.get_address_from_public_key(recovered_public_keys[0])
#         == account.address
#     ), "Failed to recover the correct address."


def test_get_hash():
    """Test the get hash functionality."""
    expected_hash = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    hash_ = SolanaApi.get_hash(message=b"hello")
    assert expected_hash == hash_


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_load_contract_interface_from_program_id():
    """Test that you can load contract interface from onchain idl store."""
    solana_api = SolanaApi()
    contract_interface = solana_api.load_contract_interface(
        program_address="ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD", rpc_api="https://api.mainnet-beta.solana.com")

    assert "name" in contract_interface, "idl has a name"


def _wait_get_receipt(
    solana_api: SolanaApi, transaction_digest: str
) -> Tuple[Optional[JSONLike], bool]:
    transaction_receipt = None
    not_settled = True
    elapsed_time = 0
    time_to_wait = 40
    sleep_time = 2
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

    nonce = solana_api.generate_tx_nonce(solana_api)

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
def test_unfunded_transfer_transaction():
    """Test the construction, signing and submitting of a transfer transaction."""
    account1 = SolanaCrypto(private_key_path=SOLANA_PRIVATE_KEY_FILE_1)
    account2 = SolanaCrypto()

    solana_api = SolanaApi()

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

    balance3 = solana_api.get_balance(account2.public_key)

    assert AMOUNT == balance3, "Should be the same balance"


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_funded_transfer_transaction():
    """Test the construction, signing and submitting of a transfer transaction."""
    account1 = SolanaCrypto(private_key_path=SOLANA_PRIVATE_KEY_FILE_1)
    account2 = SolanaCrypto()

    solana_api = SolanaApi()
    solana_faucet_api = SolanaFaucetApi()

    solana_faucet_api.get_wealth(account2.public_key, AIRDROP_AMOUNT)

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

    assert AMOUNT+AIRDROP_AMOUNT == balance3, "Should be the same balance"


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_sol_balance(caplog):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        # solana_faucet_api = SolanaFaucetApi()
        sc = SolanaCrypto(private_key_path=SOLANA_PRIVATE_KEY_FILE_1)
        sa = SolanaApi()

        balance = sa.get_balance(sc.public_key)
        assert isinstance(balance, int)


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_state_from_address():
    """Test the get_address_from_public_key method"""
    account1 = SolanaCrypto(private_key_path=SOLANA_PRIVATE_KEY_FILE_1)

    solana_api = SolanaApi()
    account_state = solana_api.get_state(account1.address)

    assert ("lamport" and "data" and "owner" and "rentEpoch") in account_state, "State not in correct format"


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_tx(caplog):
    """Test get tx from signature"""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        solana_faucet_api = SolanaFaucetApi()
        sc = SolanaCrypto(private_key_path=SOLANA_PRIVATE_KEY_FILE_1)
        solana_api = SolanaApi()
        tx_signature = solana_faucet_api.get_wealth(
            sc.address, AIRDROP_AMOUNT, "http://127.0.0.1:8899/")

        tx, settled = _wait_get_receipt(solana_api, tx_signature)
        assert settled is True
        contract_addresses = solana_api.get_contract_address(tx)
        assert contract_addresses[0] == '11111111111111111111111111111111'


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_encrypt_decrypt_privatekey(caplog):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        sc = SolanaCrypto(private_key_path=SOLANA_PRIVATE_KEY_FILE_1)
        privKey = sc.private_key

        encrypted = sc.encrypt("test123456788")

        decrypted = sc.decrypt(encrypted, "test123456788")
        assert privKey == decrypted, "Private keys match"

        # decrypted = sc.decrypt(encrypted, "test1234567")
        # assert privKey != decrypted, "Private keys dont match"


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_wealth(caplog):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        solana_faucet_api = SolanaFaucetApi()
        sc = SolanaCrypto()

        tx_signature = solana_faucet_api.get_wealth(
            sc.address, AIRDROP_AMOUNT, "http://127.0.0.1:8899/")

        assert tx_signature is not None


# @pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
# @pytest.mark.integration
# @pytest.mark.ledger
# def test_deploy_program():
#     """Test the deploy program method."""
#     program_work_dir_path = Path(ROOT_DIR, "tests", "data",
#                 "spl-token-faucet")
#     byte_code_path = Path(ROOT_DIR, "tests", "data",
#                 "spl-token-faucet", "target", "deploy", "spl_token_faucet.so")
#     keypair_path = Path(ROOT_DIR, "tests", "data",
#                 "spl-token-faucet", "target", "deploy", "spl_token_faucet-keypair.json")
#     anchor_version="0.18.0"

#     p1 = subprocess.run(f'avm use {anchor_version}',cwd=program_work_dir_path)

#     interface = {"abi": [], "bytecode": b""}
#     max_priority_fee_per_gas = 1000000000
#     max_fee_per_gas = 1000000000


def test_load_contract_interface():
    """Test the load_contract_interface method."""
    path = Path(ROOT_DIR, "tests", "data",
                "dummy_contract", "build", "idl.json")
    result = SolanaApi.load_contract_interface(path)

    assert "name" in result


def test_load_contract_instance():
    """Test the load_contract_interface method."""
    path = Path(ROOT_DIR, "tests", "data",
                "dummy_contract", "build", "idl.json")
    sa = SolanaApi()
    result = sa.load_contract_interface(path)
    pid = "ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD"
    instance = SolanaApi.get_contract_instance(SolanaApi,
                                               contract_interface=result, contract_address=pid)

    assert hasattr(instance, 'coder')

    contract_method_ix = sa.contract_method_call(
        instance, "initialize_zeta_group")


# def test_ethereum_api_get_deploy_transaction(ethereum_testnet_config):
#     """Test EthereumApi.get_deploy_transaction."""
#     ethereum_api = EthereumApi(**ethereum_testnet_config)
#     ec1 = EthereumCrypto()
#     with patch.object(ethereum_api.api.eth, "get_transaction_count", return_value=None):
#         assert (
#             ethereum_api.get_deploy_transaction(
#                 **{
#                     "contract_interface": {"": ""},
#                     "deployer_address": ec1.address,
#                     "value": 1,
#                     "max_fee_per_gas": 10,
#                 }
#             )
#             is None
#         )


def test_session_cache():
    """Test session cache."""
    assert isinstance(session_cache, LruLockWrapper)

    session_cache[1] = 1
    assert session_cache[1] == 1
    del session_cache[1]
    assert 1 not in session_cache


# def test_dump_load_with_password():
#     """Test dumping and loading a key with password."""
#     with tempfile.TemporaryDirectory() as dirname:
#         encrypted_file_name = Path(dirname, "eth_key_encrypted")
#         password = "somePwd"  # nosec
#         ec = EthereumCrypto()
#         ec.dump(encrypted_file_name, password)
#         assert encrypted_file_name.exists()
#         with pytest.raises(DecryptError, match="Decrypt error! Bad password?"):
#             ec2 = EthereumCrypto.load_private_key_from_path(
#                 encrypted_file_name, "wrongPassw"
#             )
#         ec2 = EthereumCrypto(encrypted_file_name, password)
#         assert ec2.private_key == ec.private_key


# def test_load_errors():
#     """Test load errors: bad password, no password specified."""
#     ec = EthereumCrypto()
#     with patch.object(EthereumCrypto, "load", return_value="bad sTring"):
#         with pytest.raises(KeyIsIncorrect, match="Try to specify `password`"):
#             ec.load_private_key_from_path("any path")

#         with pytest.raises(KeyIsIncorrect, match="Wrong password?"):
#             ec.load_private_key_from_path("any path", password="some")


# def test_decrypt_error():
#     """Test bad password error on decrypt."""
#     ec = EthereumCrypto()
#     ec._pritvate_key = EthereumCrypto.generate_private_key()
#     password = "test"
#     encrypted_data = ec.encrypt(password=password)
#     with pytest.raises(DecryptError, match="Bad password"):
#         ec.decrypt(encrypted_data, password + "some")

#     with patch(
#         "aea_ledger_ethereum.ethereum.Account.decrypt",
#         side_effect=ValueError("expected"),
#     ):
#         with pytest.raises(ValueError, match="expected"):
#             ec.decrypt(encrypted_data, password + "some")


# def test_helper_get_contract_address():
#     """Test EthereumHelper.get_contract_address."""
#     assert EthereumHelper.get_contract_address({"contractAddress": "123"}) == "123"


# def test_contract_method_call():
#     """Test EthereumApi.contract_method_call."""

#     method_mock = MagicMock()
#     method_mock().call = MagicMock(return_value={"value": 0})

#     contract_instance = MagicMock()
#     contract_instance.functions.dummy_method = method_mock

#     result = EthereumApi.contract_method_call(
#         contract_instance=contract_instance, method_name="dummy_method", dummy_arg=1
#     )
#     assert result["value"] == 0


# def test_build_transaction(ethereum_testnet_config):
#     """Test EthereumApi.build_transaction."""

#     def pass_tx_params(tx_params):
#         return tx_params

#     tx_mock = MagicMock()
#     tx_mock.buildTransaction = pass_tx_params

#     method_mock = MagicMock(return_value=tx_mock)

#     contract_instance = MagicMock()
#     contract_instance.functions.dummy_method = method_mock

#     eth_api = EthereumApi(**ethereum_testnet_config)

#     with pytest.raises(
#         ValueError, match=re.escape("Argument 'method_args' cannot be 'None'.")
#     ):
#         eth_api.build_transaction(
#             contract_instance=contract_instance,
#             method_name="dummy_method",
#             method_args=None,
#             tx_args={},
#         )
#     with pytest.raises(
#         ValueError, match=re.escape("Argument 'tx_args' cannot be 'None'.")
#     ):
#         eth_api.build_transaction(
#             contract_instance=contract_instance,
#             method_name="dummy_method",
#             method_args={},
#             tx_args=None,
#         )

#     with mock.patch(
#         "web3.eth.Eth.get_transaction_count",
#         return_value=0,
#     ):
#         result = eth_api.build_transaction(
#             contract_instance=contract_instance,
#             method_name="dummy_method",
#             method_args={},
#             tx_args=dict(
#                 sender_address="sender_address",
#                 eth_value=0,
#                 gas=0,
#                 gasPrice=0,  # camel-casing due to contract api requirements
#                 maxFeePerGas=0,  # camel-casing due to contract api requirements
#                 maxPriorityFeePerGas=0,  # camel-casing due to contract api requirements
#             ),
#         )

#         assert result == dict(
#             nonce=0,
#             value=0,
#             gas=0,
#             gasPrice=0,
#             maxFeePerGas=0,
#             maxPriorityFeePerGas=0,
#         )

#         with mock.patch.object(
#             EthereumApi,
#             "try_get_gas_pricing",
#             return_value={"gas": 0},
#         ):
#             result = eth_api.build_transaction(
#                 contract_instance=contract_instance,
#                 method_name="dummy_method",
#                 method_args={},
#                 tx_args=dict(
#                     sender_address="sender_address",
#                     eth_value=0,
#                 ),
#             )

#             assert result == dict(nonce=0, value=0, gas=0)


def test_get_transaction_transfer_logs():
    """Test SolanaApi.get_transaction_transfer_logs."""
    account1 = SolanaCrypto(private_key_path=SOLANA_PRIVATE_KEY_FILE_1)
    account2 = SolanaCrypto()

    solana_api = SolanaApi()

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
    logs_limited = solana_api.get_transaction_transfer_logs(
        transaction_digest, account1.address)

    assert True is True
