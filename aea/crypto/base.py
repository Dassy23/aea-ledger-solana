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
"""Abstract module wrapping the public and private key cryptography and ledger api."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Generic, Optional, Tuple, TypeVar, Union

from aea.common import Address, JSONLike
from aea.helpers.io import open_file


EntityClass = TypeVar("EntityClass")


class Crypto(Generic[EntityClass], ABC):
    """Base class for a crypto object."""

    identifier = "base"

    def __init__(
        self,
        private_key_path: Optional[str] = None,
        password: Optional[str] = None,
        extra_entropy: Union[str, bytes, int] = "",
        **kwargs: Any,
    ) -> None:  # pylint: disable=unused-argument
        """
        Initialize the crypto object.

        The actual behaviour of this constructor is determined by the abstract
        methods 'generate_private_key()' and 'load_private_key_from_path().
        Either way, the entity object will be accessible as a property.

        :param private_key_path: the path to the private key.
                If None, the key will be generated by 'generate_private_key()'.
                If not None, the path will be processed by 'load_private_key_from_path()'.
        :param password: the password to encrypt/decrypt the private key.
        :param extra_entropy: add extra randomness to whatever randomness your OS can provide
        :param kwargs: keyword arguments.
        """
        self._kwargs = kwargs
        self._entity = (
            self.generate_private_key(extra_entropy)
            if private_key_path is None
            else self.load_private_key_from_path(private_key_path, password)
        )

    @classmethod
    @abstractmethod
    def generate_private_key(
        cls, extra_entropy: Union[str, bytes, int] = ""
    ) -> EntityClass:
        """
        Generate a private key.

        :param extra_entropy: add extra randomness to whatever randomness your OS can provide
        :return: the entity object. Implementation dependent.
        """

    @classmethod
    @abstractmethod
    def load_private_key_from_path(
        cls, file_name: str, password: Optional[str] = None
    ) -> EntityClass:
        """
        Load a private key in hex format for raw private key and json format for encrypted private key from a file.

        :param file_name: the path to the hex/json file.
        :param password: the password to encrypt/decrypt the private key.
        :return: the entity object.
        """

    @property
    def entity(self) -> EntityClass:
        """
        Return an entity object.

        :return: an entity object
        """
        return self._entity

    @property
    @abstractmethod
    def private_key(self) -> str:
        """
        Return a private key.

        :return: a private key string
        """

    @property
    @abstractmethod
    def public_key(self) -> str:
        """
        Return a public key.

        :return: a public key string
        """

    @property
    @abstractmethod
    def address(self) -> str:
        """
        Return the address.

        :return: an address string
        """

    @abstractmethod
    def sign_message(self, message: bytes, is_deprecated_mode: bool = False) -> str:
        """
        Sign a message in bytes string form.

        :param message: the message to be signed
        :param is_deprecated_mode: if the deprecated signing is used
        :return: signature of the message in string form
        """

    @abstractmethod
    def sign_transaction(self, transaction: JSONLike) -> JSONLike:
        """
        Sign a transaction in dict form.

        :param transaction: the transaction to be signed
        :return: signed transaction
        """

    @classmethod
    def load(cls, private_key_file: str, password: Optional[str] = None) -> str:
        """
        Load private key from file.

        :param private_key_file: the file where the key is stored.
        :param password: the password to encrypt/decrypt the private key.
        :return: private_key in hex string format
        """
        path = Path(private_key_file)
        with open_file(path, "r") as key_file:
            data = key_file.read()
        if password is None:
            result = data
        else:
            result = cls.decrypt(data, password)
        return result

    def dump(self, private_key_file: str, password: Optional[str] = None) -> None:
        """
        Dump private key to file.

        :param private_key_file: the file where the key is stored.
        :param password: the password to encrypt/decrypt the private key.
        """
        if password is None:
            with open(private_key_file, "wb") as fpb:
                fpb.write(self.private_key.encode("utf-8"))
        else:
            with open_file(private_key_file, "w") as fp:
                encrypted = self.encrypt(password)
                fp.write(encrypted)

    @abstractmethod
    def encrypt(self, password: str) -> str:
        """
        Encrypt the private key and return in json.

        :param password: the password to decrypt.
        :return: json string containing encrypted private key.
        """

    @classmethod
    @abstractmethod
    def decrypt(cls, keyfile_json: str, password: str) -> str:
        """
        Decrypt the private key and return in raw form.

        :param keyfile_json: json string containing encrypted private key.
        :param password: the password to decrypt.
        :return: the raw private key.
        """


class Helper(ABC):
    """Interface for helper class usable as Mixin for LedgerApi or as standalone class."""

    @staticmethod
    @abstractmethod
    def is_transaction_settled(tx_receipt: JSONLike) -> bool:
        """
        Check whether a transaction is settled or not.

        :param tx_receipt: the receipt associated to the transaction.
        :return: True if the transaction has been settled, False o/w.
        """

    @staticmethod
    @abstractmethod
    def is_transaction_valid(
        tx: JSONLike,
        seller: Address,
        client: Address,
        tx_nonce: str,
        amount: int,
    ) -> bool:
        """
        Check whether a transaction is valid or not.

        :param tx: the transaction.
        :param seller: the address of the seller.
        :param client: the address of the client.
        :param tx_nonce: the transaction nonce.
        :param amount: the amount we expect to get from the transaction.
        :return: True if the random_message is equals to tx['input']
        """

    @staticmethod
    @abstractmethod
    def get_contract_address(tx_receipt: JSONLike) -> Optional[str]:
        """
        Get the contract address from a transaction receipt.

        :param tx_receipt: the transaction digest
        :return: the contract address if successful
        """

    @staticmethod
    @abstractmethod
    def generate_tx_nonce(seller: Address, client: Address) -> str:
        """
        Generate a unique hash to distinguish transactions with the same terms.

        :param seller: the address of the seller.
        :param client: the address of the client.
        :return: return the hash in hex.
        """

    @classmethod
    @abstractmethod
    def get_address_from_public_key(cls, public_key: str) -> str:
        """
        Get the address from the public key.

        :param public_key: the public key
        :return: str
        """

    @classmethod
    @abstractmethod
    def recover_message(
        cls, message: bytes, signature: str, is_deprecated_mode: bool = False
    ) -> Tuple[Address, ...]:
        """
        Recover the addresses from the hash.

        :param message: the message we expect
        :param signature: the transaction signature
        :param is_deprecated_mode: if the deprecated signing was used
        :return: the recovered addresses
        """

    @classmethod
    @abstractmethod
    def recover_public_keys_from_message(
        cls, message: bytes, signature: str, is_deprecated_mode: bool = False
    ) -> Tuple[str, ...]:
        """
        Get the public key used to produce the `signature` of the `message`

        :param message: raw bytes used to produce signature
        :param signature: signature of the message
        :param is_deprecated_mode: if the deprecated signing was used
        :return: the recovered public keys
        """

    @staticmethod
    @abstractmethod
    def get_hash(message: bytes) -> str:
        """
        Get the hash of a message.

        :param message: the message to be hashed.
        :return: the hash of the message.
        """

    @classmethod
    @abstractmethod
    def is_valid_address(cls, address: Address) -> bool:
        """
        Check if the address is valid.

        :param address: the address to validate
        """

    @classmethod
    @abstractmethod
    def load_contract_interface(cls, file_path: Path) -> Dict[str, str]:
        """
        Load contract interface.

        :param file_path: the file path to the interface
        :return: the interface
        """


class LedgerApi(Helper, ABC):
    """Interface for ledger APIs."""

    identifier = "base"  # type: str

    @property
    @abstractmethod
    def api(self) -> Any:
        """
        Get the underlying API object.

        This can be used for low-level operations with the concrete ledger APIs.
        If there is no such object, return None.
        """

    @abstractmethod
    def get_balance(
        self, address: Address, raise_on_try: bool = False
    ) -> Optional[int]:
        """
        Get the balance of a given account.

        This usually takes the form of a web request to be waited synchronously.

        :param address: the address.
        :param raise_on_try: whether the method will raise or log on error
        :return: the balance.
        """

    @abstractmethod
    def get_state(
        self, callable_name: str, *args: Any, raise_on_try: bool = False, **kwargs: Any
    ) -> Optional[JSONLike]:
        """
        Call a specified function on the underlying ledger API.

        This usually takes the form of a web request to be waited synchronously.

        :param callable_name: the name of the API function to be called.
        :param args: the positional arguments for the API function.
        :param raise_on_try: whether the method will raise or log on error
        :param kwargs: the keyword arguments for the API function.
        :return: the ledger API response.
        """

    @abstractmethod
    def get_transfer_transaction(
        self,
        sender_address: Address,
        destination_address: Address,
        amount: int,
        tx_fee: int,
        tx_nonce: str,
        **kwargs: Any,
    ) -> Optional[JSONLike]:
        """
        Submit a transfer transaction to the ledger.

        :param sender_address: the sender address of the payer.
        :param destination_address: the destination address of the payee.
        :param amount: the amount of wealth to be transferred.
        :param tx_fee: the transaction fee.
        :param tx_nonce: verifies the authenticity of the tx
        :param kwargs: the keyword arguments.
        :return: the transfer transaction
        """

    @abstractmethod
    def send_signed_transaction(
        self, tx_signed: JSONLike, raise_on_try: bool = False
    ) -> Optional[str]:
        """
        Send a signed transaction and wait for confirmation.

        Use keyword arguments for the specifying the signed transaction payload.

        :param tx_signed: the signed transaction
        :param raise_on_try: whether the method will raise or log on error
        :return: tx_digest, if present
        """

    @abstractmethod
    def get_transaction_receipt(
        self, tx_digest: str, raise_on_try: bool = False
    ) -> Optional[JSONLike]:
        """
        Get the transaction receipt for a transaction digest.

        :param tx_digest: the digest associated to the transaction.
        :param raise_on_try: whether the method will raise or log on error
        :return: the tx receipt, if present
        """

    @abstractmethod
    def get_transaction(
        self, tx_digest: str, raise_on_try: bool = False
    ) -> Optional[JSONLike]:
        """
        Get the transaction for a transaction digest.

        :param tx_digest: the digest associated to the transaction.
        :param raise_on_try: whether the method will raise or log on error
        :return: the tx, if present
        """

    @abstractmethod
    def get_contract_instance(
        self, contract_interface: Dict[str, str], contract_address: Optional[str] = None
    ) -> Any:
        """
        Get the instance of a contract.

        :param contract_interface: the contract interface.
        :param contract_address: the contract address.
        :return: the contract instance
        """

    @abstractmethod
    def get_deploy_transaction(
        self,
        contract_interface: Dict[str, str],
        deployer_address: Address,
        raise_on_try: bool = False,
        **kwargs: Any,
    ) -> Optional[JSONLike]:
        """
        Get the transaction to deploy the smart contract.

        :param contract_interface: the contract interface.
        :param deployer_address: The address that will deploy the contract.
        :param raise_on_try: whether the method will raise or log on error
        :param kwargs: the keyword arguments.
        :returns tx: the transaction dictionary.
        """

    @abstractmethod
    def update_with_gas_estimate(self, transaction: JSONLike) -> JSONLike:
        """
        Attempts to update the transaction with a gas estimate

        :param transaction: the transaction
        :return: the updated transaction
        """

    @abstractmethod
    def contract_method_call(
        self,
        contract_instance: Any,
        method_name: str,
        **method_args: Any,
    ) -> Optional[JSONLike]:
        """Call a contract's method

        :param contract_instance: the contract to use
        :param method_name: the contract method to call
        :param method_args: the contract call parameters
        """

    @abstractmethod
    def build_transaction(
        self,
        contract_instance: Any,
        method_name: str,
        method_args: Optional[Dict],
        tx_args: Optional[Dict],
        raise_on_try: bool = False,
    ) -> Optional[JSONLike]:
        """Prepare a transaction

        :param contract_instance: the contract to use
        :param method_name: the contract method to call
        :param method_args: the contract parameters
        :param tx_args: the transaction parameters
        :param raise_on_try: whether the method will raise or log on error
        """

    @abstractmethod
    def get_transaction_transfer_logs(
        self,
        contract_instance: Any,
        tx_hash: str,
        target_address: Optional[str] = None,
    ) -> Optional[JSONLike]:
        """
        Get all transfer events derived from a transaction.

        :param contract_instance: the contract
        :param tx_hash: the transaction hash
        :param target_address: optional address to filter transfer events to just those that affect it
        """


class FaucetApi(ABC):
    """Interface for testnet faucet APIs."""

    identifier = "base"  # type: str
    network_name = "testnet"  # type: str

    @abstractmethod
    def get_wealth(self, address: Address, url: Optional[str] = None) -> None:
        """
        Get wealth from the faucet for the provided address.

        :param address: the address.
        :param url: the url
        :return: None
        """
