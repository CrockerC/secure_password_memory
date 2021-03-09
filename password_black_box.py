import Crypto
import AES as aes


class password_black_box:
    def __init__(self):
        self.path = 'users\\'

    def new_user(self, user, password):
        key = self.hash(password)
        id = self.encrypt(key)
        with open(self.path + user, 'w') as f:
            f.write(id)

    def verify(self, user, password):
        try:
            with open(self.path + user, 'r') as f:
                # todo, protect this from huge files
                id = f.read()
                key = self.hash(password)
                message = self.decrypt(id, key)
                if message == "Congratulations! You got the password correct!":
                    return key
                else:
                    return False
        except FileNotFoundError:
            return False

    @staticmethod
    def hash(password):
        key = Crypto.Hash.SHA256.new(data=bytes(password, 'utf-8')).digest()
        return key

    @staticmethod
    def decrypt(data, key):
        try:
            return str(aes.decryptAES(data, key), 'utf-8')
        except UnicodeDecodeError:
            return False

    @staticmethod
    def encrypt(key):
        message = "Congratulations! You got the password correct!"
        return aes.encryptAES(bytes(message, 'utf-8'), key)


if __name__ == '__main__':
    black_box = password_black_box()

    # test 1
    black_box.new_user(user="big_fudge", password="thats_my_name")
    print(black_box.verify(user="big_fudge", password="thats_my_name") is not False)

    # test 2
    black_box.new_user(user="teddy_westside_123!@", password="ase!@ds!3154")
    print(black_box.verify(user="teddy_westside_123!@", password="ase!@ds!3154") is not False)

    # test 3
    black_box.new_user(user="teddy_westside_123!@", password="ase!@ds!3154")
    print(black_box.verify(user="teddy_westside_123!@", password="ase!@ds!314") is not False)

    # test 4
    black_box.new_user(user="big_fudge_123", password="thats_my_name")
    print(black_box.verify(user="teddy_westside", password="ase!@ds!314") is not False)

    # test 5
    black_box.new_user(user="big_fudge_123", password="thats_my_name")
    print(black_box.verify(user="big_fudge_123", password="ase!@ds!314") is not False)

