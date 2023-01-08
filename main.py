from solana.keypair import Keypair
from anchorpy import Idl
import json
from anchorpy import Program, Context
from solana.rpc.api import Client
from typing import NewType
from solders.hash import Hash
from solders.transaction import Transaction as sTransaction
import time
from solana.publickey import PublicKey
from solana.transaction import Transaction

converted = True


def to_dict_tx(txn):
    tx = txn.to_json()
    # tx = json.loads(tx)
    return tx


def to_tx(tx):
    # jsonTx = json.dumps(tx)
    stxn = sTransaction.from_json(tx)
    # tx = Transaction.from_solders(stxn)
    return stxn


def test_contract_method_call_v1():

    p1 = Keypair.from_secret_key(
        b"\xcaX3N\xc9%\xd8\xfb\xb3\xfd\xb9\xb5E\xd4\x16\xdd\xf4R\xd0\xce\xc7|\xb3h\x10\xa6\xa6\xac\xf0\xe0Y\xf6?\x91\x82w\x12c\xc2\xa4>L\xb1\x02w\xf7\x0bX\xad{U,\xa6\xca\xbb\xdb\x98E\x07\xb0\xfe'P\xfb")
    print(p1.public_key.to_base58().decode())
    p2 = Keypair.from_secret_key(
        b'\x1f_Ru\xc5\xc9\xb5l\x90\x042,\xbaA\x871\x9c\xe7\x84\x10\xe7C\xe4\xfe\xa9\xe4\x11S,\xf02\xb4\xf1J5!\xf6\x04W\xcd\xba%$\xe8M\xac\x03\xfc\x98\xa3\xf8\xf5!\xb7\x90|M\xad\xe5\xe5\x89uC\x99')
    print(p2.public_key.to_base58().decode())
    game = Keypair.generate()
    f = open('tic_tac_toe.json')

    json_idl = json.load(f)

    program_id = PublicKey("AT9foczNVnZCLyxuHr2PoVKswZV84jhXrvV3H3vYeEag")
    idl = Idl.from_json(json.dumps(json_idl))
    pg = Program(idl, program_id)

    Commitment = NewType("Commitment", str)
    Confirmed = Commitment("confirmed")
    api = Client(
        endpoint="https://api.devnet.solana.com", commitment=Confirmed
    )

    pg.provider.wallet = p1

    result = api.get_latest_blockhash()
    result_val = result.value
    solders_blockhash = result_val.blockhash

    nonce_c = list(bytes(solders_blockhash))

    nonce = str(solders_blockhash)
    accounts = {
        "game": game.public_key,
        "player": p1.public_key
    }

    tile = pg.type['Tile'](row=0, column=0)

    tx = pg.transaction['play'](tile, ctx=Context(
        accounts=accounts))
    stx = tx._solders
    tx_c = to_dict_tx(stx)

    tx_c['message']['recentBlockhash'] = nonce_c

    # tx_c.update({'message': {'recentBlockhash': nonce_c}})
    # tx_c['message']['header']['numReadonlySignedAccounts'] = 0
    tx_c = to_tx(tx_c)

    tx.recent_blockhash = nonce
    print(tx._solders.message.header.to_json())
    print(tx_c.message.header.to_json())

    assert tx == tx_c, "Not equal"


test_contract_method_call_v1()
