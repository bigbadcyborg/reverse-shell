import sys

def customEncryptDecrypt(shellcode_bytes, N, D):
    # Encrypt/Decrypt each byte in the shellcode
    encrypted_shellcode = bytearray()
    for byte in shellcode_bytes:
        shifted_byte = (byte + (D * N)) % 256
        encrypted_shellcode.append(shifted_byte)
    return bytes(encrypted_shellcode)  # Return as bytes


def process_shellcode_file(filename, N, D):
    try:
        # Open the shellcode file and read its raw contents
        with open(filename, 'rb') as file:
            shellcode_bytes = file.read()

        # Encrypt or decrypt the shellcode
        result_shellcode = customEncryptDecrypt(shellcode_bytes, N, D)

        # Overwrite the original file with the encrypted/decrypted shellcode
        with open(filename, 'wb') as file:  # Write in binary mode
            file.write(result_shellcode)  # Write the raw bytes

        print(f"File '{filename}' has been modified with the encrypted/decrypted shellcode.")

    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


def main():
    try:
        # Check if enough arguments are provided
        if len(sys.argv) != 3:
            raise ValueError("Usage: python3 encrypt-decrypt.py <N> <D>")

        # Get command line arguments
        N = int(sys.argv[1])
        D = int(sys.argv[2])

        # Validate inputs
        if N < 1:
            raise ValueError("N must be a positive integer (>= 1).")
        if D not in [1, -1]:
            raise ValueError("D can only be +1 (encryption) or -1 (decryption).")

        # Specify the shellcode file name
        filename = "shellcode.c"

        # Process the shellcode file
        process_shellcode_file(filename, N, D)

    except ValueError as error:
        print(f"Input Error: {error}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# Run the main function
if __name__ == "__main__":
    main()
