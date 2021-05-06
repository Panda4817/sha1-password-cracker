import hashlib
from os import curdir
import pathlib

current_dir = str(pathlib.Path(__file__).parent)
passwords = [i for i in open(current_dir +
                             "/top-10000-passwords.txt", "r").read().split("\n")]

known_salts = [i for i in open(current_dir +
                               "/known-salts.txt", "r").read().split("\n")]


def compare_hash(hash, password):
    h = hashlib.sha1(password).hexdigest()
    if h == hash:
        return True
    return False


def crack_sha1_hash(hash, use_salts=False):
    global passwords, known_salts

    for password in passwords:
        p = password.encode('utf-8')
        if use_salts:
            for salt in known_salts:
                ps = salt.encode() + p
                if compare_hash(hash, ps):
                    return password
                ps = p + salt.encode()
                if compare_hash(hash, ps):
                    return password
        else:
            if compare_hash(hash, p):
                return password

    return "PASSWORD NOT IN DATABASE"
