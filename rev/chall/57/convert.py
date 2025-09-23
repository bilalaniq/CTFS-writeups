input_num = 39722847074734820757600524178581224432297292490103995897672826024691504153

# Multiply by 5 (or whatever operation)
output_num = input_num * 5

# Convert to hex string and remove '0x'
hex_string = hex(output_num)[2:]

# Ensure even length
if len(hex_string) % 2 != 0:
    hex_string = '0' + hex_string

# Convert to ASCII (ignore non-ASCII bytes)
flag = bytes.fromhex(hex_string).decode('ascii', errors='ignore')

print(flag)
