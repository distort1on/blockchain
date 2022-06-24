import sha1
import RSA_Digital_Sign

class KeyPair():
    def gen_key_pair(self, size = 1024, type = "rsa"):
        """
        :param size: nbits key length
        :param type: type of digital sign (will be more sign types)
        :return: key pair (private key, public key)
        """
        self.__private_key, self.public_key = RSA_Digital_Sign.create_keys(size)
        return self.__private_key, self.public_key

    def print_key_pair(self):
        print(f'Private key - {self.__private_key}\nPublic key - {self.public_key}')

    def get_private_key(self):
        return self.__private_key

    def get_public_key(self):
        return self.public_key

    def get_key_pair(self):
        return self.__private_key, self.public_key


class Sign():
    @staticmethod
    def sign_data(private_key, message, type = "rsa"):
        return RSA_Digital_Sign.create_digital_signature(message, private_key)

    @staticmethod
    def verifySignature(public_key, message, signature, type = "rsa"):
        return RSA_Digital_Sign.verify_signature(message, signature, public_key)




if __name__ == '__main__':
    # I'm using my own implementation of RSA digital sign

    keys = KeyPair()
    private_key, public_key = keys.gen_key_pair(1024)

    data = "test"
    signature = Sign.sign_data(private_key, data)

    print(Sign.verifySignature(public_key, data, signature))







