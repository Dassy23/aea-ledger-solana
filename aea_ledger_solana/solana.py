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
"""Solana module wrapping the public and private key cryptography and ledger api."""
import decimal
import json
import logging
import hashlib
import base64

import threading
import warnings
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union, cast
from uuid import uuid4
from ast import literal_eval
import zlib


from aea.common import Address, JSONLike
from aea.crypto.base import Crypto, FaucetApi, Helper, LedgerApi
from aea.crypto.helpers import DecryptError, KeyIsIncorrect, hex_to_bytes_for_key
from aea.exceptions import enforce
from aea.helpers import http_requests as requests
from aea.helpers.base import try_decorator
from aea.helpers.io import open_file

from solana.publickey import PublicKey
from solana.rpc.api import Client
from solana.rpc import types
from solana.keypair import Keypair
from solders.signature import Signature
from anchorpy import Idl
from cryptography.fernet import Fernet


from pathlib import Path
import json
from solana.blockhash import Blockhash
from solana.transaction import Transaction
from anchorpy import Program
from anchorpy.idl import _decode_idl_account, _idl_address
from anchorpy.coder.accounts import ACCOUNT_DISCRIMINATOR_SIZE
from solana.system_program import TransferParams, transfer
from solana.transaction import Transaction
from solana.system_program import create_account, SYS_PROGRAM_ID
from solana.system_program import CreateAccountParams


from lru import LRU
import web3._utils.request
from web3 import Web3


_default_logger = logging.getLogger(__name__)

_SOLANA = "solana"
TESTNET_NAME = "testnet"
DEFAULT_ADDRESS = "http://127.0.0.1:8899"
DEFAULT_CHAIN_ID = "solana"
DEFAULT_CURRENCY_DENOM = "lamports"
RENT_EXEMPT_AMOUNT = 1000000
_IDL = "idl"
_BYTECODE = "bytecode"


def _pako_inflate(data):
    # https://stackoverflow.com/questions/46351275/using-pako-deflate-with-python
    decompress = zlib.decompressobj(15)
    decompressed_data = decompress.decompress(data)
    decompressed_data += decompress.flush()
    return decompressed_data


class SolanaCrypto(Crypto[Keypair]):
    """Class wrapping the Account Generation from Solana ledger."""

    identifier = _SOLANA

    def __init__(
        self,
        private_key_path: Optional[str] = None,
        password: Optional[str] = None,
        extra_entropy: Union[str, bytes, int] = "",
    ) -> None:
        """
        Instantiate an solana crypto object.

        :param private_key_path: the private key path of the agent
        :param password: the password to encrypt/decrypt the private key.
        :param extra_entropy: add extra randomness to whatever randomness your OS can provide
        """
        super().__init__(
            private_key_path=private_key_path,
            password=password,
            extra_entropy=extra_entropy,
        )
        bytes_representation = self.entity.secret_key
        self._public_key = self.entity.public_key
        self._address = self.entity.public_key

    @property
    def private_key(self) -> str:
        """
        Return a private key.

        64 random hex characters (i.e. 32 bytes) prefix.

        :return: a private key string in hex format
        """

        return self.entity.secret_key.hex()

    @property
    def public_key(self) -> str:
        """
        Return a public key in hex format.


        :return: a public key string in hex format
        """
        return self._public_key

    @property
    def address(self) -> str:
        """
        Return the address for the key pair.

        40 hex characters (i.e. 20 bytes) + "0x" prefix.

        :return: an address string in hex format
        """
        return self._address.to_base58().decode()

    @classmethod
    def load_private_key_from_path(
        cls, file_name: str, password: Optional[str] = None
    ) -> Keypair:
        """
        Load a private key in base58 format from a file.

        :param file_name: the path to the hex file.
        :param password: the password to encrypt/decrypt the private key.
        :return: the Entity.
        """
        private_key = open(file_name, "r").read()

        try:
            key = Keypair.from_secret_key(private_key.encode("utf-8"))
        except Exception as e:

            raise KeyIsIncorrect(
                f"Error on key `{file_name}` load! : Error: {repr(e)} "
            ) from e

        return key

    def sign_message(self, message: bytes, is_deprecated_mode: bool = False) -> str:
        """
        Sign a message in bytes string form.

        :param message: the message to be signed
        :param is_deprecated_mode: if the deprecated signing is used
        :return: signature of the message in string form
        """

        keypair = Keypair.from_secret_key(bytes.fromhex(self.private_key))
        signed_msg = keypair.sign(message)

        return signed_msg

    def sign_transaction(self, transaction: JSONLike, recent_blockhash: Blockhash, signers: Optional[list] = []) -> JSONLike:
        """
        Sign a transaction in bytes string form.

        :param transaction: the transaction to be signed
        :param recent_blockhash: a recent blockhash
        :return: signed transaction
        """

        keypair = Keypair.from_secret_key(bytes.fromhex(self.private_key))
        signers = [Keypair.from_secret_key(bytes.fromhex(
            signer.private_key)) for signer in signers]
        transaction.recent_blockhash = recent_blockhash
        signers.append(keypair)
        try:
            transaction.sign(*signers)
        except Exception as e:
            print(e)
            raise Exception(e)
        return transaction

    def sign_partial(self, transaction: JSONLike, recent_blockhash: Blockhash) -> JSONLike:
        """
        Sign a transaction in bytes string form.

        :param transaction: the transaction to be signed
        :param recent_blockhash: a recent blockhash
        :return: signed transaction
        """

        keypair = Keypair.from_secret_key(bytes.fromhex(self.private_key))
        transaction.recent_blockhash = recent_blockhash
        transaction.sign_partial(keypair)

        return transaction

    @ classmethod
    def generate_private_key(
        cls, extra_entropy: Union[str, bytes, int] = ""
    ) -> Keypair:
        """
        Generate a key pair for Solana network.

        :param extra_entropy: add extra randomness to whatever randomness your OS can provide
        :return: keypair object
        """
        account = Keypair.generate()  # pylint: disable=no-value-for-parameter
        return account

    def encrypt(self, password: str) -> str:
        """
        Encrypt the private key and return in json.

        :param password: the password to decrypt.
        :return: json string containing encrypted private key.
        """
        try:
            pw = str.encode(password)
            hash_object = hashlib.sha256(pw)
            hex_dig = hash_object.digest()
            base64_bytes = base64.b64encode(hex_dig)
            fernet = Fernet(base64_bytes)
            enc_mac = fernet.encrypt(self.private_key.encode())
        except Exception as e:
            raise Exception("Encryption failed")

        return json.dumps(enc_mac.decode())

    @ classmethod
    def decrypt(cls, keyfile_json: str, password: str) -> str:
        """
        Decrypt the private key and return in raw form.

        :param keyfile_json: json str containing encrypted private key.
        :param password: the password to decrypt.
        :return: the raw private key.
        """
        try:
            keyfile = json.loads(keyfile_json)
            keyfile_bytes = keyfile.encode()
            pw = str.encode(password)
            hash_object = hashlib.sha256(pw)
            hex_dig = hash_object.digest()
            base64_bytes = base64.b64encode(hex_dig)
            fernet = Fernet(base64_bytes)

            dec_mac = fernet.decrypt(keyfile_bytes).decode()
        except ValueError as e:
            raise DecryptError() from e
        return dec_mac


class SolanaHelper(Helper):
    """Helper class usable as Mixin for SolanaApi or as standalone class."""

    @classmethod
    def load_contract_interface(cls,
                                file_path: Optional[Path] = None,
                                program_address: Optional[str] = None,
                                rpc_api: Optional[str] = None,
                                ) -> Dict[str, str]:
        """
        Load contract interface.

        :param file_path: the file path to the interface
        :return: the interface
        """
        contract_interface = None
        if program_address is not None and rpc_api is not None:
            try:
                base = PublicKey.find_program_address(
                    [], PublicKey(program_address))[0]
                idl_address = PublicKey.create_with_seed(
                    base, "anchor:idl", PublicKey(program_address))
                client = Client(endpoint=rpc_api)
                account_info = client.get_account_info(idl_address)

                account_info_val = account_info.value
                idl_account = _decode_idl_account(
                    bytes(account_info_val.data)[
                        ACCOUNT_DISCRIMINATOR_SIZE:]
                )
                inflated_idl = _pako_inflate(
                    bytes(idl_account["data"])).decode()
                json_idl = json.loads(inflated_idl)
                return json_idl
            except Exception as e:
                raise Exception("Could not locate IDL")

        elif file_path is not None:
            with open_file(file_path, "r") as interface_file_solana:
                contract_interface = json.load(interface_file_solana)
            return contract_interface
        else:
            raise Exception("Could not locate IDL")

    @ staticmethod
    def is_transaction_valid(
        tx: dict
    ) -> bool:
        """
        Check whether a transaction is valid or not.

        :param tx: the transaction.
        :return: True if the random_message is equals to tx['input']
        """
        is_valid = False
        if tx is not None:
            # is_valid = (
            #     tx.get("input") == tx_nonce
            #     and tx.get("value") == amount
            #     and tx.get("from") == client
            #     and tx.get("to") == seller
            # )
            is_valid = True
        return is_valid

    @ staticmethod
    def is_transaction_settled(tx_receipt: JSONLike) -> bool:
        """
        Check whether a transaction is settled or not.

        :param tx_receipt: the receipt associated to the transaction.
        :return: True if the transaction has been settled, False o/w.
        """
        is_successful = False
        if tx_receipt is not None:
            is_successful = tx_receipt['meta']['status'] == {
                'Ok': None}
        return is_successful

    @ staticmethod
    def get_hash(message: bytes) -> str:
        """
        Get the hash of a message.

        :param message: the message to be hashed.
        :return: the hash of the message as a hex string.
        """
        digest = Web3.keccak(message).hex()
        return digest

    @classmethod
    def recover_message(
        cls, message: bytes, signature: str, is_deprecated_mode: bool = False
    ) -> Tuple[Address, ...]:
        """
        **TOBEIMPLEMENTED**
        Recover the addresses from the hash.

        :param message: the message we expect
        :param signature: the transaction signature
        :param is_deprecated_mode: if the deprecated signing was used
        :return: the recovered addresses
        """

        # try:
        #     pass
        #     # VerifyKey(bytes(self.address)).verify(msg.message, msg.signature)
        # except:
        #     return False
        return True

    @classmethod
    def recover_public_keys_from_message(
        cls, message: bytes, signature: str, is_deprecated_mode: bool = False
    ) -> Tuple[str, ...]:
        """
        **TOBEIMPLEMENTED**
        Get the public key used to produce the `signature` of the `message`

        :param message: raw bytes used to produce signature
        :param signature: signature of the message
        :param is_deprecated_mode: if the deprecated signing was used
        :return: the recovered public keys
        """
        # if not is_deprecated_mode:
        #     signable_message = encode_defunct(primitive=message)
        #     message = _hash_eip191_message(signable_message)
        # hash_bytes = HexBytes(message)
        # # code taken from https://github.com/ethereum/eth-account/blob/master/eth_account/account.py#L428
        # if len(hash_bytes) != 32:  # pragma: nocover
        #     raise ValueError("The message hash must be exactly 32-bytes")
        # signature_bytes = HexBytes(signature)
        # signature_bytes_standard = to_standard_signature_bytes(signature_bytes)
        # signature_obj = keys.Signature(signature_bytes=signature_bytes_standard)
        # pubkey = signature_obj.recover_public_key_from_msg_hash(hash_bytes)
        return "TOBEIMPLEMENTED"

    @ staticmethod
    def generate_tx_nonce(self) -> str:
        """
        Generate a unique hash to distinguish transactions with the same terms.

        :param self: .
        :param client: the address of the client.
        :return: return the hash in hex.
        """

        result = self._api.get_latest_blockhash()
        blockhash_json = result.value.to_json()
        blockhash = json.loads(blockhash_json)
        hash = blockhash['blockhash']
        return hash

    @ staticmethod
    def get_contract_address(tx_receipt: JSONLike) -> Optional[list[str]]:
        """
        Retrieve the `contract_addresses` from a transaction receipt.
        **Solana can have many contract addresses in one tx**

        :param tx_receipt: the receipt of the transaction.
        :return: the contract address, if present
        """
        contract_addresses = []
        keys = tx_receipt['transaction']['message']['accountKeys']
        for ix in tx_receipt['transaction']['message']['instructions']:
            program_index = ix['programIdIndex']
            contract_addresses.append(keys[program_index])
        return contract_addresses

    @ classmethod
    def get_address_from_public_key(cls, public_key: PublicKey) -> str:
        """
        Get the address from the public key.

        :param public_key: the public key
        :return: str
        """

        return public_key.to_base58().decode()

    @ classmethod
    def is_valid_address(cls, address: Address) -> bool:
        """
        Check if the address is valid.
        **TOBEIMPLEMENTED**

        :param address: the address to validate
        :return: whether the address is valid
        """
        # address = self.get
        return True


class SolanaApi(LedgerApi, SolanaHelper):
    """Class to interact with the Solana Web3 APIs."""

    identifier = _SOLANA

    def __init__(self, **kwargs: Any):
        """
        Initialize the Solana ledger APIs.

        :param kwargs: keyword arguments
        """
        self._api = Client(
            endpoint=kwargs.pop("address", DEFAULT_ADDRESS)
        )
        self._chain_id = kwargs.pop("chain_id", DEFAULT_CHAIN_ID)

    @property
    def api(self) -> Web3:
        """Get the underlying API object."""
        return self._api

    def update_with_gas_estimate(self, transaction: JSONLike) -> JSONLike:
        """
        **DO NOT NEED**
        Attempts to update the transaction with a gas estimate

        :param transaction: the transaction
        :return: the updated transaction
        """
        # gas_estimate = self._try_get_gas_estimate(transaction)
        # if gas_estimate is not None:
        #     transaction["gas"] = gas_estimate
        return transaction

    def get_balance(
        self, address: Address, raise_on_try: bool = False
    ) -> Optional[int]:
        """Get the balance of a given account."""
        return self._try_get_balance(address, raise_on_try=raise_on_try)

    @try_decorator("Unable to retrieve balance: {}", logger_method="warning")
    def _try_get_balance(self, address: Address, **_kwargs: Any) -> Optional[int]:
        """Get the balance of a given account."""
        response = self._api.get_balance(address)  # pylint: disable=no-member
        return response.value

    # def get_token_balances(
    #     self, address: Address, raise_on_try: bool = False
    # ) -> list:
    #     """Get the balance of a given account."""
    #     return self._try_get_token_balances(address, raise_on_try=raise_on_try)

    # @try_decorator("Unable to retrieve balance: {}", logger_method="warning")
    # def _try_get_token_balances(self, address: Address, **_kwargs: Any) -> list:
    #     """Get the token balances of a given owner."""
    #     txOpts = types.TokenAccountOpts(program_id=PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'))
    #     response = self._api.get_token_accounts_by_owner_json_parsed(PublicKey(address),opts=txOpts)  # pylint: disable=no-member
    #     balances = []
    #     for key in response.value:
    #         balance = json.loads(key.account.data.parsed)
    #         balances.append(
    #             {
    #                 "mint": balance['info']['mint'],
    #                 "balance":balance['info']['tokenAmount']['uiAmount']
    #             }
    #             )

    #     return balances

    def get_state(
        self, address: str, *args: Any, raise_on_try: bool = False, **kwargs: Any
    ) -> Optional[JSONLike]:
        """Call a specified function on the ledger API."""
        response = self._try_get_state(
            address, *args, raise_on_try=raise_on_try, **kwargs
        )
        return response

    @try_decorator("Unable to get state: {}", logger_method="warning")
    def _try_get_state(  # pylint: disable=unused-argument
        self, address: str, *args: Any, **kwargs: Any
    ) -> Optional[JSONLike]:
        """Try to call a function on the ledger API."""

        if "raise_on_try" in kwargs:
            logging.info(
                f"popping `raise_on_try` from {self.__class__.__name__}.get_state kwargs"
            )
            kwargs.pop("raise_on_try")

        account_object = self._api.get_account_info_json_parsed(
            PublicKey(address))
        account_info_val = json.loads(account_object.value.to_json())
        return account_info_val

    def get_transfer_transaction(  # pylint: disable=arguments-differ
        self,
        sender_address: Address,
        destination_address: Address,
        amount: int,
        unfunded_account: bool,
        chain_id: Optional[int] = None,
        raise_on_try: bool = False,
        **kwargs: Any,
    ) -> Optional[JSONLike]:
        """
        Submit a transfer transaction to the ledger.

        :param sender_address: the sender address of the payer.
        :param destination_address: the destination address of the payee.
        :param amount: the amount of wealth to be transferred (in Lamports).
        :param chain_id: the Chain ID of the Ethereum transaction.
        :param raise_on_try: whether the method will raise or log on error
        :param kwargs: keyword arguments
        :return: the transfer transaction
        """
        chain_id = chain_id if chain_id is not None else self._chain_id

        if unfunded_account:
            destination_balance = self.get_balance(destination_address)
            if destination_balance != 0:
                raise Exception("Account is already funded")

        if unfunded_account and amount > RENT_EXEMPT_AMOUNT:
            params = CreateAccountParams(
                from_pubkey=PublicKey(sender_address),
                new_account_pubkey=PublicKey(destination_address),
                lamports=RENT_EXEMPT_AMOUNT,
                space=1,
                program_id=SYS_PROGRAM_ID
            )
            createAccountInstruction = create_account(params)
            txn = Transaction(fee_payer=sender_address).add(createAccountInstruction).add(transfer(TransferParams(
                from_pubkey=PublicKey(sender_address), to_pubkey=PublicKey(destination_address), lamports=amount-RENT_EXEMPT_AMOUNT)))

        elif unfunded_account and amount < RENT_EXEMPT_AMOUNT:
            raise Exception("Not enough funds sent to initialize account")
        else:
            txn = Transaction(fee_payer=sender_address).add(transfer(TransferParams(
                from_pubkey=PublicKey(sender_address), to_pubkey=PublicKey(destination_address), lamports=amount)))

        return txn

    def send_signed_transaction(
        self, tx_signed: JSONLike, raise_on_try: bool = False
    ) -> Optional[str]:
        """
        Send a signed transaction and wait for confirmation.

        :param tx_signed: the signed transaction
        :param raise_on_try: whether the method will raise or log on error
        :return: tx_digest, if present
        """
        tx_digest = self._try_send_signed_transaction(
            tx_signed, raise_on_try=raise_on_try
        )
        tx = json.loads(tx_digest)
        return tx['result']

    @ try_decorator("Unable to send transaction: {}", logger_method="warning")
    def _try_send_signed_transaction(
        self, tx_signed: JSONLike, **_kwargs: Any
    ) -> Optional[str]:
        """
        Try send a signed transaction.

        :param tx_signed: the signed transaction
        :param _kwargs: the keyword arguments. Possible kwargs are:
            `raise_on_try`: bool flag specifying whether the method will raise or log on error (used by `try_decorator`)
        :return: tx_digest, if present
        """
        try:
            # txOpts = types.TxOpts(skip_preflight=True)

            txn_resp = self._api.send_raw_transaction(
                tx_signed.serialize())
        except Exception as e:
            raise Exception(e)
        return txn_resp.to_json()

    def get_transaction_receipt(
        self, tx_digest: str, raise_on_try: bool = False
    ) -> Optional[JSONLike]:
        """
        Get the transaction receipt for a transaction digest.

        :param tx_digest: the digest associated to the transaction.
        :param raise_on_try: whether the method will raise or log on error
        :return: the tx receipt, if present
        """
        tx_receipt = self._try_get_transaction_receipt(
            tx_digest,
            raise_on_try=raise_on_try,
        )

        return tx_receipt

    @ try_decorator(
        "Error when attempting getting tx receipt: {}", logger_method="debug"
    )
    def _try_get_transaction_receipt(
        self, tx_digest: str, **_kwargs: Any
    ) -> Optional[JSONLike]:
        """
        Try get the transaction receipt.

        :param tx_digest: the digest associated to the transaction.
        :param _kwargs: the keyword arguments. Possible kwargs are:
            `raise_on_try`: bool flag specifying whether the method will raise or log on error (used by `try_decorator`)
        :return: the tx receipt, if present
        """
        try:
            tx_receipt = self._api.get_transaction(
                Signature.from_string(tx_digest))  # pylint: disable=no-member
        except Exception as e:
            print(e)
        tx = json.loads(tx_receipt.to_json())
        return tx["result"]

    def get_transaction(
        self,
        tx_digest: str,
        raise_on_try: bool = False,
    ) -> Optional[JSONLike]:
        """
        Get the transaction for a transaction digest.

        :param tx_digest: the digest associated to the transaction.
        :param raise_on_try: whether the method will raise or log on error
        :return: the tx, if present
        """
        tx = self._try_get_transaction(tx_digest, raise_on_try=raise_on_try)
        return tx

    @ try_decorator("Error when attempting getting tx: {}", logger_method="debug")
    def _try_get_transaction(
        self, tx_digest: str, **_kwargs: Any
    ) -> Optional[JSONLike]:
        """
        Get the transaction.

        :param tx_digest: the transaction digest.
        :param _kwargs: the keyword arguments. Possible kwargs are:
            `raise_on_try`: bool flag specifying whether the method will raise or log on error (used by `try_decorator`)
        :return: the tx, if found
        """
        try:
            tx = self._api.get_transaction(Signature.from_string(tx_digest))
        except Exception as e:
            print(e)
        # pylint: disable=no-member
        return json.loads(tx.value.to_json())

    def get_contract_instance(
        self, contract_interface: Dict[str, str], contract_address: str
    ) -> Any:
        """
        Get the instance of a contract.

        :param contract_interface: the contract interface.
        :param contract_address: the contract address.
        :return: the contract instance
        """

        program_id = PublicKey(contract_address)
        idl = Idl.from_json(json.dumps(contract_interface))
        pg = Program(idl, program_id)

        return pg

    def get_deploy_transaction(  # pylint: disable=arguments-differ
        self,
        contract_interface: Dict[str, str],
        deployer_address: Address,
        raise_on_try: bool = False,
        **kwargs: Any,
    ) -> Optional[JSONLike]:
        """

        **TOBEIMPLEMENTED**
        Get the transaction to deploy the smart contract.

        :param contract_interface: the contract interface.
        :param deployer_address: The address that will deploy the contract.
        :param raise_on_try: whether the method will raise or log on error
        :param kwargs: keyword arguments
        :return: the transaction dictionary.
        """

        return {}

    @ classmethod
    def contract_method_call(
        cls,
        contract_instance: Any,
        method_name: str,
        **method_args: Any,
    ) -> Optional[JSONLike]:
        """Call a contract's method
        **TOBEIMPLEMENTED**

        :param contract_instance: the contract to use
        :param method_name: the contract method to call
        :param method_args: the contract call parameters
        :return: the call result
        """

        return {}

    def build_transaction(  # pylint: disable=too-many-arguments
        self,
        contract_instance: Any,
        method_name: str,
        method_args: Optional[Dict[Any, Any]],
        tx_args: Optional[Dict[Any, Any]],
        raise_on_try: bool = False,
    ) -> Optional[JSONLike]:
        """Prepare a transaction
        **TOBEIMPLEMENTED**

        :param contract_instance: the contract to use
        :param method_name: the contract method to call
        :param method_args: the contract parameters
        :param tx_args: the transaction parameters
        :param raise_on_try: whether the method will raise or log on error
        :return: the transaction
        """

        return {}

    def get_transaction_transfer_logs(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        tx_hash: str,
        target_address: Optional[str] = None,
    ) -> Optional[JSONLike]:
        """
        Get all transfer events derived from a transaction.

        :param tx_hash: the transaction hash
        :param target_address: optional address to filter tranfer events to just those that affect it
        :return: the transfer logs
        """
        try:
            tx_receipt = self.get_transaction_receipt(tx_hash)
            if tx_receipt is None:
                raise ValueError  # pragma: nocover

        except (Exception, ValueError):  # pragma: nocover
            return dict()

        keys = tx_receipt['transaction']['message']['accountKeys']
        if target_address:
            transfers = {
                "preBalances": [
                    {"address": keys[idx], "balance":balance} for idx, balance in enumerate(tx_receipt['meta']['preBalances'])
                    if keys[idx] == target_address

                ],
                "postBalances": [
                    {"address": keys[idx], "balance":balance} for idx, balance in enumerate(tx_receipt['meta']['postBalances'])
                    if keys[idx] == target_address

                ]
            }
        else:
            transfers = {
                "preBalances": [
                    {"address": keys[idx], "balance":balance} for idx, balance in enumerate(tx_receipt['meta']['preBalances'])
                ],
                "postBalances": [
                    {"address": keys[idx], "balance":balance} for idx, balance in enumerate(tx_receipt['meta']['postBalances'])
                ]
            }

        return transfers


class SolanaFaucetApi(FaucetApi):
    """Solana testnet faucet API."""

    identifier = _SOLANA
    testnet_name = TESTNET_NAME

    def get_wealth(self, address: Address, amount: int, url: Optional[str] = None) -> None:
        """
        Get wealth from the faucet for the provided address.

        :param address: the address.
        :param url: the url
        """

        return self._try_get_wealth(address, amount, url)

    @ staticmethod
    @ try_decorator(
        "An error occured while attempting to generate wealth:\n{}",
        logger_method="error",
    )
    def _try_get_wealth(address: Address, amount: int, url: Optional[str] = None) -> str or None:
        """
        Get wealth from the faucet for the provided address.

        :param address: the address.
        :param url: the url
        """
        if url is None:
            url = DEFAULT_ADDRESS

        solana_client = Client(url)
        response = None
        try:
            resp = solana_client.request_airdrop(
                address, amount)
        except Exception as e:
            msg = e
            pass
        response = (json.loads(resp.to_json()))
        if response['result'] == None:
            _default_logger.error("Response: {}".format("airdrop failed"))
        elif "error" in response:  # pragma: no cover
            _default_logger.error("Response: {}".format("airdrop failed"))
        elif "result" in response:  # pragma: nocover

            _default_logger.warning(
                "Response: {}\nMessage: {}".format(
                    "success", response['result']
                )
            )
            return response['result']


class LruLockWrapper:
    """Wrapper for LRU with threading.Lock."""

    def __init__(self, lru: LRU) -> None:
        """Init wrapper."""
        self.lru = lru
        self.lock = threading.Lock()

    def __getitem__(self, *args: Any, **kwargs: Any) -> Any:
        """Get item"""
        with self.lock:
            return self.lru.__getitem__(*args, **kwargs)

    def __setitem__(self, *args: Any, **kwargs: Any) -> Any:
        """Set item."""
        with self.lock:
            return self.lru.__setitem__(*args, **kwargs)

    def __contains__(self, *args: Any, **kwargs: Any) -> Any:
        """Contain item."""
        with self.lock:
            return self.lru.__contains__(*args, **kwargs)

    def __delitem__(self, *args: Any, **kwargs: Any) -> Any:
        """Del item."""
        with self.lock:
            return self.lru.__delitem__(*args, **kwargs)


def set_wrapper_for_web3py_session_cache() -> None:
    """Wrap web3py session cache with threading.Lock."""

    # pylint: disable=protected-access
    web3._utils.request._session_cache = LruLockWrapper(
        web3._utils.request._session_cache
    )


set_wrapper_for_web3py_session_cache()
