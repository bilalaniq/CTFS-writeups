import ast

# Load scrambled data from file
with open("enc.txt", "r") as f:
    scrambled = ast.literal_eval(f.read())

result = []

for i, current in enumerate(scrambled):
    if i == 0:
        # First element has 2 useful values
        result.extend(current[:2])
    elif len(current) >= 3:
        # Take first and third values
        result.extend([current[0], current[2]])
    elif len(current) == 2:
        # Take only first value
        result.append(current[0])

# Convert hex → ASCII string
flag = "".join(
    chr(int(val, 16)) for val in result
    if isinstance(val, str) and val.startswith("0x")
)

print(flag)
