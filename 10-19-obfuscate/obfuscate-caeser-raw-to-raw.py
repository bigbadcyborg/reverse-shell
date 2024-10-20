def caesar_cipher(data, shift):
    return bytes((byte + shift) % 256 for byte in data)

def main():
    input_file = 'shellcode.raw'
    output_file = 'obfuscated_shellcode.raw'
    shift = 33  # Change this to your desired shift value

    with open(input_file, 'rb') as f:
        shellcode = f.read()

    obfuscated_shellcode = caesar_cipher(shellcode, shift)

    with open(output_file, 'wb') as f:
        f.write(obfuscated_shellcode)

    print(f"Shellcode obfuscated and saved to {output_file}")

if __name__ == "__main__":
    main()
