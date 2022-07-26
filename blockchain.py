#  Copyright (c) 2022. Illia Popov.

import sha1
import RSA_Digital_Sign


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

        key_pair = KeyPair.gen_key_pair()
        self.account_id = Hash.to_sha1(str(key_pair.get_public_key()[0]) + str(key_pair.get_public_key()[1]))

        self.__wallet.append(key_pair)

    @classmethod
    def gen_account(cls):
        return Account()

    def add_key_pair_to_wallet(self, key_pair):
        self.__wallet.append(key_pair)

    def create_operation(self, document, wallet_index):
        signature = Sign.sign_data(self.__wallet[wallet_index].get_private_key(), document)
        return Operation.create_operation(self, document, signature)

    def sign_data(self, data, wallet_index):
        return Sign.sign_data(self.__wallet[wallet_index].get_private_key(), data)

    def print_keys(self):
        for keys in self.__wallet:
            keys.to_string()

    def get_public_key(self, key_index):
        return self.__wallet[key_index].get_public_key()

    def get_wallet_size(self):
        return len(self.__wallet)

    def to_string(self):
        result_string = ""
        result_string += f'Account object:\n\tAccount id: {self.account_id}\n\tWallet:\n'

        for index in range(len(self.__wallet)):
            result_string += self.__wallet[index].to_string()

        return result_string


class Operation:
    def __init__(self, sender : Account, data, signature):

        # Доказательство владения документом
        self.sender = sender
        self.signature = signature

        #дату переделать#######################################################################3
        self.data = data
        self.operation_id = Hash.to_sha1(str(data) + str(signature) + str(sender.account_id))

    @classmethod
    def create_operation(cls, sender, data, signature):
        return Operation(sender, data, signature)


    @staticmethod
    def verify_operation(operation):

        # Проверка подписи
        for index in range(operation.sender.get_wallet_size()):
            if RSA_Digital_Sign.verify_signature(operation.data, operation.signature, operation.sender.get_public_key(index)) == True:
                return True
        return False

        # Защита от дублирования

    def to_string(self):
        result_string = ""
        result_string += f"Operation object:\n\tSender:\n"
        result_string += self.sender.to_string()
        result_string += f'\tData:\n{self.data}\n\tSignature:\n{self.signature}'
        return result_string


class Transaction:
    # Защита от дублирования транзакции происходит после ее формирования (проверяется валидность подписи и
    # отсутсвие данного документа в блокчейне) для каждой операции
    # Транзакция также подписывается
    def __init__(self, set_of_operations, sender : Account, wallet_index):
        self.set_of_operations = set_of_operations
        self.sender = sender

        operations_id = ""
        for operation in set_of_operations:
            operations_id += operation.operation_id

        self.transaction_id = Hash.to_sha1(str(operations_id))
        self.signature = self.sender.sign_data(self.transaction_id, wallet_index)

    @classmethod
    def create_transaction(cls, set_of_operarions, sender : Account, wallet_index):
        return Transaction(set_of_operarions, sender, wallet_index)

    @staticmethod
    def verify_transaction(transaction):
        for operation in transaction.set_of_operations:
            if Operation.verify_operation(operation) == False:
                return False
        return True








class Hash:
    @staticmethod
    def to_sha1(data):
        return sha1.sha1_hash(data)









if __name__ == '__main__':
    # I'm using my own implementation of RSA digital sign

    illia = Account.gen_account()
    sign = illia.sign_data("test", 0)
    is_valid = Sign.verify_signature(illia.get_public_key(0), "test", sign)
    print(is_valid)

    illia.add_key_pair_to_wallet(KeyPair.gen_key_pair())
    illia.print_keys()

    private_key, public_key = KeyPair.gen_key_pair().get_key_pair()

    data = "test2"
    signature = Sign.sign_data(private_key, data)
    print(Sign.verify_signature(public_key, data, signature))


    print("--------------------------")
    data = "message"
    signature = illia.sign_data(data, 1)
    oper = illia.create_operation(data, 1)

    print("result")
    print(Operation.verify_operation(oper))
    print(oper.to_string())
    #oper.to_string()