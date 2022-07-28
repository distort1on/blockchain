from blockchain import *
import logging
import hashlib
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(message)s')

# {document hash} : {transaction_id} для быстрой проверки наличия документа в блокчейне
documentsDatabase = {}

# Каждому аккаунту присвоено имя для облегчения ввода команд пользователя
accounts = {}  # {name} : {account_id}
pool = []
NUM_OF_TRANSACTIONS_IN_BLOCK = 3
BLOCK_REWARD = 5


def get_document_hash(document):
    h = hashlib.sha1()
    with open(document, 'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h.update(chunk)
    return h.hexdigest()


start_test_commands = ["/createAccount Illia", "/createAccount Dima", "/getFaucetCoins Illia 10",
                       "/getFaucetCoins Dima 10", "/createTransaction Illia Dima 0 2",
                       "/createTransaction Illia Dima 0 1", "/addDocument Illia 0 stepik-certificate-512-0907a9f.pdf",
                       "/verifyDocument stepik-certificate-512-0907a9f.pdf", "/verifyDocument sha1.py", "/showCoinDatabase"]

# Команды для тестирования программы
coommands = [
    "/createAccount",  # + {nickname}
    "/createTransaction",  # + {sender nickname} + {receiver nickname} + {wallet_index} + {amount} + {data (additional)}
    "/clearPool",
    "/getFaucetCoins",  # + {user nickname} + {amount}
    "/stop",
    "/transactionDetails",  # + {transaction_id}
    "/accountDetails",  # + {nickname}
    "/printBlockchain",
    "/showCoinDatabase",
    "/addDocument",  # + {user nickname} + {wallet index} + {document path}
    "/verifyDocument",  # + {document path}

]

if __name__ == '__main__':
    # I'm using my own implementation of RSA digital sign and sha1 (not with documents)

    miner = Account.gen_account()
    accounts["miner"] = miner

    bitcoin_blockChain = Blockchain.init_blockchain(50, miner)
    bitcoin_blockChain.add_account_to_coin_database(miner)

    while True:
        if len(start_test_commands) != 0:
            user_input = start_test_commands[0].split(" ")
            start_test_commands.pop(0)
        else:
            # time.sleep(2)
            user_input = input().split(" ")

        if user_input[0] in coommands:

            if user_input[0] == "/createAccount":
                user = Account.gen_account()
                bitcoin_blockChain.add_account_to_coin_database(user)
                accounts[user_input[1]] = user

                logging.info(f"Created account: {user_input[1]}\n" + user.to_string())

            elif user_input[0] == "/createTransaction":

                if len(user_input) == 6:
                    _, sender, receiver, wallet_index, amount, data = user_input
                else:
                    _, sender, receiver, wallet_index, amount = user_input
                    data = ""

                tx = Transaction.create_transaction(accounts[sender], accounts[receiver], int(wallet_index),
                                                    float(amount), data)

                if Transaction.verify_transaction(tx):
                    pool.append(tx)
                    logging.info(f'Created transaction {tx.transaction_id} and added to pool')
                else:
                    logging.info("Transaction error")

            elif user_input[0] == "/getFaucetCoins":
                try:
                    _, account, amount = user_input
                    bitcoin_blockChain.get_token_from_faucet(accounts[account], float(amount))
                    logging.info(f'Successfully added {amount} coins to {account} : {accounts[account].account_id}')
                except Exception as e:
                    print(e)
            elif user_input[0] == "/clearPool":
                pool.clear()

            elif user_input[0] == "/transactionDetails":
                try:
                    logging.info(bitcoin_blockChain.tx_database[user_input[1]].to_string())
                except KeyError:
                    print("Transaction does not exists")

            elif user_input[0] == "/accountDetails":
                try:
                    logging.info(accounts[user_input[1]].to_string())
                except KeyError:
                    print("Account does not exists")

            elif user_input[0] == "/showCoinDatabase":
                logging.info(bitcoin_blockChain.show_coin_database())

            elif user_input[0] == "/printBlockchain":
                for block in bitcoin_blockChain.block_history:
                    logging.info(block.to_string())

            elif user_input[0] == "/addDocument":
                _, sender, wallet_index, filename = user_input
                document_hash = get_document_hash(filename)

                tx = Transaction.create_transaction(accounts[sender], accounts['miner'], int(wallet_index), 0,
                                                    document_hash)

                if Transaction.verify_transaction(tx):
                    pool.append(tx)
                    logging.info(
                        f"Your document successfully added to pool and waiting for adding to blockchain.\nDocument id "
                        f"(transaction id) - {tx.transaction_id}")

                    logging.info(f'Created transaction {tx.transaction_id} and added to pool')
                    documentsDatabase[document_hash] = tx.transaction_id
                else:
                    logging.info("Transaction error")

            elif user_input[0] == "/verifyDocument":
                try:
                    document_hash = get_document_hash(user_input[1])
                    tx_id = documentsDatabase[document_hash]

                    tx = bitcoin_blockChain.tx_database[tx_id]
                    if tx == bitcoin_blockChain.tx_database[tx_id]:
                        logging.info(f'Your document іs in blockchain')
                        logging.info(tx.to_string())
                except KeyError:
                    logging.info("Your document isn't in blockchain or its changed")

            elif user_input[0] == "/stop":
                break

        if len(pool) == NUM_OF_TRANSACTIONS_IN_BLOCK:
            new_block = Block.create_block(bitcoin_blockChain.block_history[-1].block_id, pool, BLOCK_REWARD,
                                           accounts["miner"])
            error_str = bitcoin_blockChain.validate_block(new_block)

            if len(error_str) != 0:
                logging.info(error_str)
            else:
                pool.clear()
                logging.info(f'Block successfully added to blockchain')
                logging.info(bitcoin_blockChain.block_history[-1].to_string())
