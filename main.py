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

    def print_key_pair(self):
        print(f'Private key - {self.__private_key}\nPublic key - {self.public_key}\n-----')

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
        self.account_id = key_pair.get_public_key()

        self.__wallet.append(key_pair)

    @classmethod
    def gen_account(cls):
        return Account()

    def add_key_pair_to_wallet(self, key_pair):
        self.__wallet.append(key_pair)

    def create_operation(self, document, wallet_index):
        pass

    def sign_data(self, data, wallet_index):
        return Sign.sign_data(self.__wallet[wallet_index].get_private_key(), data)

    def print_keys(self):
        for keys in self.__wallet:
            keys.print_key_pair()

    def get_public_key(self, key_index):
        return self.__wallet[key_index].get_public_key()


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
