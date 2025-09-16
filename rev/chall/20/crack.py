output = "qhcpgbpuwbaggepulhstxbwowawfgrkzjstccbnbshekpgllze"
secret1 = 85
secret2 = 51
secret3 = 15
fix = 97

pw_chars = []
for i_0, ch in enumerate(output):
    m = i_0 % 255
    random1 = (secret1 & m) + (secret1 & (m >> 1))
    random2 = (random1 & secret2) + (secret2 & (random1 >> 2))
    A = random2 & secret3
    B = secret3 & (random2 >> 4)
    # invert three rounds:
    original_ch = ((ord(ch) - fix - 3*(A + B)) % 26) + fix
    pw_chars.append(chr(original_ch))

password = "".join(pw_chars)
print(password)
