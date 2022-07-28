#  Copyright (c) 2022. Illia Popov.
import random
import sha1
import RSA_Digital_Sign
import calendar
import datetime


class KeyPair:
    def __init__(self, size=1024, sign_type="rsa"):
        """
        :param size: nbits key length
        :param sign_type: type of digital sign (will be more sign types)
        :return: key pair (private key, public key)
        """
        self.__private_key, self.public_key = RSA_Digital_Sign.create_keys(size)

    @classmethod
    def gen_key_pair(cls, size=1024, sign_type="rsa"):
        return KeyPair(size, sign_type)

    def to_string(self):
        return f'-----Private key - {self.__private_key}\nPublic key - {self.public_key}-----\n'

    def get_private_key(self):
        return self.__private_key

    def get_public_key(self):
        return self.public_key

    def get_key_pair(self):
        return self.__private_key, self.public_key


class Sign:
    @staticmethod
    def sign_data(private_key, message, sign_type="rsa"):
        return RSA_Digital_Sign.create_digital_signature(message, private_key)

    @staticmethod
    def verify_signature(public_key, message, signature, sign_type="rsa"):
        return RSA_Digital_Sign.verify_signature(message, signature, public_key)


class Account:

    def __init__(self):
        self.__wallet = []
        self.balance = 0

        key_pair = KeyPair.gen_key_pair()
        self.account_id = Hash.to_sha1(str(key_pair.get_public_key()[0]) + str(key_pair.get_public_key()[1]))
        self.__wallet.append(key_pair)

    @classmethod
    def gen_account(cls):
        return Account()

    def add_key_pair_to_wallet(self, key_pair):
        self.__wallet.append(key_pair)

    def create_transaction(self, receiver, amount, wallet_index, data=""):
        return Transaction.create_transaction(self, receiver, wallet_index, amount, data)

    def sign_data(self, data, wallet_index):
        return Sign.sign_data(self.__wallet[wallet_index].get_private_key(), data)

    def print_keys(self):
        for keys in self.__wallet:
            keys.to_string()

    def get_public_key(self, key_index):
        return self.__wallet[key_index].get_public_key()

    def get_wallet_size(self):
        return len(self.__wallet)

    def get_balance(self):
        return self.balance

    def update_balance(self, new_balance):
        self.balance = new_balance

    def to_string(self):
        result_string = ""
        result_string += f'Account object:\n\tAccount id: {self.account_id}\n\tBalance: {self.balance}\n\tWallet:\n'

        for index in range(len(self.__wallet)):
            result_string += self.__wallet[index].to_string()

        return result_string


class Transaction:
    def __init__(self, sender: Account, receiver: Account, wallet_index, amount, data=""):

        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.transaction_fee = 0.5
        # Упрощение OP_RETURN (в операцию можно вставить дополнительные данные)
        self.data = data
        self.nonce = int(calendar.timegm(datetime.datetime.utcnow().utctimetuple())) + random.randrange(1, 1000)

        # coinBase_transaction
        if sender is None:
            self.sender = None
            self.transaction_fee = 0
            try:
                self.transaction_id = Hash.to_sha1(
                    str(self.receiver.account_id) + str(self.amount) + str(self.transaction_fee) + self.data + str(
                        self.nonce))
                self.signature = self.receiver.sign_data(self.transaction_id, wallet_index)
            except AttributeError:
                # Genedis block coinBase transaction
                self.transaction_id = Hash.to_sha1(str(self.amount) + self.data + str(self.nonce))
                self.signature = None

        else:
            self.transaction_id = Hash.to_sha1(
                str(self.sender.account_id) + str(self.receiver.account_id) + str(self.amount) + str(
                    self.transaction_fee) + str(self.data) + str(self.nonce))
            self.signature = self.sender.sign_data(self.transaction_id, wallet_index)

    @classmethod
    def create_transaction(cls, sender, receiver, wallet_index, amount, data=""):
        return Transaction(sender, receiver, wallet_index, amount, data)

    @classmethod
    def create_coinbase_transaction(cls, receiver, amount):
        return Transaction(None, receiver, 0, amount, 'coinBase')

    @staticmethod
    def verify_transaction(transaction):
        # Проверка подписи
        for index in range(transaction.sender.get_wallet_size()):
            if RSA_Digital_Sign.verify_signature(transaction.transaction_id, transaction.signature,
                                                 transaction.sender.get_public_key(index)) == False:
                return False

        # Траты не превышают баланс
        if transaction.sender.get_balance() < (transaction.amount + transaction.transaction_fee):
            return False

        return True
        # Защита от дублирования, доказательство владения  - при проверке блока

    def to_string(self):
        if self.sender is None:
            return f'Transaction object (coinBase):\n\tTransacton id:\n\t\t{self.transaction_id}\n\t' \
                   f'Sender:\n\t\t{self.sender}\n\tReceiver:\n\t\t{self.receiver.account_id}' \
                   f'\n\tAmount:\n\t\t{self.amount}\n\tFee:\n\t\t{self.transaction_fee}\n\tData:\n\t\t{self.data}' \
                   f'\n\tNonce:\n\t\t{self.nonce}\n\tSignature:\n\t\t{self.signature}'

        return f'Transaction object:\n\tTransacton id:\n\t\t{self.transaction_id}\n\tSender:\n\t\t{self.sender.account_id}' \
               f'\n\tReceiver:\n\t\t{self.receiver.account_id}\n\tAmount:\n\t\t{self.amount}\n\tFee:\n\t\t{self.transaction_fee}' \
               f'\n\tData:\n\t\t{self.data}\n\tNonce:\n\t\t{self.nonce}\n\tSignature:\n\t\t{self.signature}'


class Block:
    def __init__(self, prev_hash, set_of_transactions, block_reward, miner: Account):
        # Блок получает список правильных и подтвержденных транзакций и сразу хеширует
        self.block_id = ""
        self.prev_hash = prev_hash
        self.set_of_transactions = set_of_transactions[:]
        self.timestamp = calendar.timegm(datetime.datetime.utcnow().utctimetuple())
        self.nonce = 0

        coinBase_transaction = Transaction.create_coinbase_transaction(miner, block_reward)
        self.set_of_transactions.insert(0, coinBase_transaction)
        self.transaction_counter = len(set_of_transactions)

        self.result_str = str(self.prev_hash) + str(self.transaction_counter) + str(self.timestamp)
        for transaction in self.set_of_transactions:
            self.result_str += str(transaction.transaction_id)

        # PoW
        while True:
            self.block_id = sha1.sha1_hash(self.result_str + str(self.nonce))
            if self.block_id[0:3] == "000":
                break

            self.nonce += 1

    @classmethod
    def create_block(cls, prev_hash, set_of_transactions, block_reward, miner: Account):
        return Block(prev_hash, set_of_transactions, block_reward, miner)

    def to_string(self):
        to_str = f'Block object:\n\tBlock id:\n\t\t{self.block_id}\n\tPrev block hash:\n\t\t{self.prev_hash}' \
                 f'\n\tNum of transactions:\n\t\t{self.transaction_counter}\n\tTime:\n\t\t{self.timestamp}\n\tTransactions:'

        for transaction in self.set_of_transactions:
            to_str += f'\n\t\tTX ID : {str(transaction.transaction_id)}'

        return to_str


class Blockchain:
    def __init__(self, genesis_block, faucet_coins):
        self.coin_database = {}
        self.block_history = []
        self.block_history.append(genesis_block)
        self.tx_database = {}
        self.faucet_coins = faucet_coins
        # Для упрощения реализации utxo и доказательство владения монетами, при добавлении транзакции 
        # (получения или отправки монет) в блокчейн, ее id добавится в
        # user_transaction_history, где восстановив историю поступления и списания монет можно будет убедиться в 
        # актуальном состоянии баланса пользователя
        self.user_transaction_history = {}

    @classmethod
    def init_blockchain(cls, faucet_coins, miner: Account):
        genesis_block = Block.create_block("00000000000000000000", [], 0, miner)
        return Blockchain(genesis_block, faucet_coins)

    def get_token_from_faucet(self, account, amount):
        if amount <= self.faucet_coins:
            tx = Transaction.create_coinbase_transaction(account, amount)

            account.update_balance(account.get_balance() + amount)

            self.user_transaction_history[account.account_id].append(tx)
            self.coin_database[account.account_id] = account.get_balance()

    def validate_block(self, block):
        error_str = ""

        if block.prev_hash != self.block_history[-1].block_id:
            return "Wrong block hash"

        for transaction in block.set_of_transactions:
            if transaction.sender is None:
                continue

            if transaction in self.tx_database:
                block.set_of_transactions.remove(transaction)
                error_str += f'TX {transaction.transaction_id} is already exist in database. removed\n'

            # Проверка на право владения монетами отправителя транзакции
            r_amount = self.check_user_amount_by_history(transaction.sender)

            if transaction.sender.get_balance() != r_amount:
                transaction.sender.update_balance(r_amount)
                error_str += f'Transaction {transaction.transaction_id} sender {transaction.sender.account_id} ' \
                             f'has wrong balance. Changed\n'

                if transaction.sender.get_balance() < (transaction.amount + transaction.transaction_fee):
                    block.set_of_transactions.remove(transaction)
                    error_str += f'Sender {transaction.sender.account_id} not enough coins. removed'

        # all ok
        if len(error_str) == 0:
            self.block_history.append(block)
            reward = block.set_of_transactions[0].amount

            for transaction in block.set_of_transactions:
                if transaction.sender is None:
                    self.tx_database[transaction.transaction_id] = transaction
                    continue

                self.tx_database[transaction.transaction_id] = transaction

                transaction.sender.update_balance(
                    transaction.sender.get_balance() - (transaction.amount + transaction.transaction_fee))
                transaction.receiver.update_balance(transaction.receiver.get_balance() + transaction.amount)

                self.user_transaction_history[transaction.sender.account_id].append(transaction)
                self.user_transaction_history[transaction.receiver.account_id].append(transaction)

                self.coin_database[transaction.sender.account_id] = transaction.sender.get_balance()
                self.coin_database[transaction.receiver.account_id] = transaction.receiver.get_balance()

                reward += transaction.transaction_fee

            miner = block.set_of_transactions[0].receiver
            miner.update_balance(miner.get_balance() + reward)

            self.coin_database[miner.account_id] = miner.get_balance()
            self.user_transaction_history[miner.account_id].append(block.set_of_transactions[0])

        return error_str

    def show_coin_database(self):
        result_str = ""
        for key in self.coin_database.keys():
            result_str += f'{str(key)} - {str(self.coin_database[key])} coins\n'

        return result_str

    def add_account_to_coin_database(self, account: Account):
        self.coin_database[account.account_id] = 0
        self.user_transaction_history[account.account_id] = []

    def check_user_amount_by_history(self, account: Account):
        r_amount = 0

        for transaction in self.user_transaction_history[account.account_id]:
            if transaction.sender == account:
                r_amount -= (transaction.amount + transaction.transaction_fee)
            elif transaction.receiver == account:
                r_amount += (transaction.amount)

        return r_amount


class Hash:
    @staticmethod
    def to_sha1(data):
        return sha1.sha1_hash(data)





