# Solana crypto plug-in

Solana crypto plug-in for the AEA framework.

## Install

```bash
python setup.py install
```

## Run tests

```bash
python setup.py test
```

## Start

```bash
pipenv --python 3.10 && pipenv shell
```

## Build and Start testnet docker image

```bash
docker build ./tests/data/ test-ledger
```

```bash
docker run -d -p 8899:8899 -p 8900:8900 test-ledger
```
