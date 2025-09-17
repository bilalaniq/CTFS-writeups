import hashlib

username = b"FREEMAN"
hash_hex = hashlib.sha256(username).hexdigest()
print(hash_hex[4])
print(hash_hex[5])
print(hash_hex[3])
print(hash_hex[6])
print(hash_hex[2])
print(hash_hex[7])
print(hash_hex[1])
print(hash_hex[8])



# picoCTF{1n_7h3_|<3y_of_0d208392}

