scrambled = "jU5t_a_sna_3lpm12g94c_u_4_m7ra41"

def recover(scrambled):
    password = ['?'] * 32

    # 1) for (i=0; i<8; i++) buffer[i] = password.charAt(i)
    #    => password[i] = buffer[i]
    for i in range(0, 8):
        password[i] = scrambled[i]

    # 2) for (; i<16; i++) buffer[i] = password.charAt(23 - i)
    #    => password[23 - i] = buffer[i]
    for i in range(8, 16):
        password[23 - i] = scrambled[i]

    # 3) for (; i<32; i+=2) buffer[i] = password.charAt(46 - i)
    #    => password[46 - i] = buffer[i]
    for i in range(16, 32, 2):
        password[46 - i] = scrambled[i]

    # 4) for (i=31; i>=17; i-=2) buffer[i] = password.charAt(i)
    #    => password[i] = buffer[i]
    for i in range(31, 16, -2):   # stop=16 to include 17
        password[i] = scrambled[i]

    return "".join(password)

print("Recovered password:", recover(scrambled))
