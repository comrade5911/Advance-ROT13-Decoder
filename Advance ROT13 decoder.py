import codecs
import re
import string
import os

# Function to decode ROT13
def decode_rot13(text):
    return codecs.decode(text, 'rot_13')

# Function to check if a decoded string is meaningful
def is_valid_decoded_string(decoded):
    # Ensure it contains valid letters, spaces, or backslashes
    return any(char.isalpha() for char in decoded) and all(char in string.printable for char in decoded)

# Function to extract and decode ROT13 strings from a file
def extract_and_decode_rot13(input_file, output_file):
    decoded_strings = []
    
    # Open the input file and process line by line
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            # Extract quoted strings (potentially encoded) using regex
            matches = re.findall(r'["\']([A-Za-z\\ ]{5,})["\']', line)
            for encoded in matches:
                decoded = decode_rot13(encoded)
                if is_valid_decoded_string(decoded):  # Only keep valid decoded text
                    decoded_strings.append(f"Encoded: {encoded} → Decoded: {decoded}")

    # Save decoded results to a file (write only if there are results)
    if decoded_strings:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(decoded_strings))
        print(f"\n✅ Decoded strings saved to: {output_file}")
    else:
        print("\n⚠️ No valid ROT13-encoded strings found!")

# Function to extract ASCII strings from a file (EXE or other binary)
def extract_ascii_strings(input_file):
    ascii_strings = []
    
    # Open the binary file and search for ASCII strings
    with open(input_file, 'rb') as f:
        byte_data = f.read()
        matches = re.findall(b'[\x20-\x7E]{4,}', byte_data)  # Match ASCII strings of length 4 or more
        ascii_strings = [match.decode('utf-8', errors='ignore') for match in matches]

    return ascii_strings

# Function to decode Base64 strings
def decode_base64(encoded_string):
    try:
        decoded = codecs.decode(encoded_string, 'base64').decode('utf-8', errors='ignore')
        return decoded
    except Exception as e:
        return f"⚠️ Error decoding Base64: {e}"

# Function to extract and decode Base64 strings from a file
def extract_and_decode_base64(input_file, output_file):
    decoded_strings = []
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            # Extract Base64-encoded strings using regex
            matches = re.findall(r'([A-Za-z0-9+/=]{20,})', line)
            for encoded in matches:
                decoded = decode_base64(encoded)
                decoded_strings.append(f"Encoded: {encoded} → Decoded: {decoded}")

    # Save decoded results to a file (write only if there are results)
    if decoded_strings:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(decoded_strings))
        print(f"\n✅ Decoded Base64 strings saved to: {output_file}")
    else:
        print("\n⚠️ No valid Base64-encoded strings found!")

# Interactive mode for manual input
def interactive_mode():
    while True:
        user_input = input("\nEnter a ROT13-encoded string (or type 'exit' to quit): ")
        if user_input.lower() == "exit":
            break
        decoded = decode_rot13(user_input)
        if is_valid_decoded_string(decoded):
            print(f"✅ Decoded: {decoded}")
        else:
            print("⚠️ Invalid or already decoded string.")

# Main function to select mode
def main():
    print("\n📌 Choose an option:")
    print("1️⃣ Decode ROT13 from a text file (IDA Pro disassembly output)")
    print("2️⃣ Decode Base64 from a text file")
    print("3️⃣ Extract and decode ASCII strings from an EXE file")
    print("4️⃣ Batch decode multiple ROT13 strings")
    print("5️⃣ Interactive mode (Manually input ROT13 strings)")

    choice = input("\nEnter 1, 2, 3, 4, or 5: ")

    if choice == "1":
        input_file = input("\nEnter the filename (e.g., ida_disassembly.txt): ")
        output_file = input("\nEnter the output file name (e.g., decoded_strings.txt): ")
        extract_and_decode_rot13(input_file, output_file)
    
    elif choice == "2":
        input_file = input("\nEnter the filename (e.g., base64_strings.txt): ")
        output_file = input("\nEnter the output file name (e.g., decoded_base64.txt): ")
        extract_and_decode_base64(input_file, output_file)

    elif choice == "3":
        input_file = input("\nEnter the EXE filename: ")
        ascii_strings = extract_ascii_strings(input_file)
        if ascii_strings:
            print("\n✅ Extracted ASCII Strings:")
            for string in ascii_strings:
                print(f"🔹 {string}")
        else:
            print("\n⚠️ No ASCII strings found!")

    elif choice == "4":
        print("\n📌 Enter multiple ROT13-encoded strings (one per line). Type 'DONE' when finished:\n")
        encoded_strings = []
        while True:
            user_input = input("> ")
            if user_input.lower() == "done":
                break
            encoded_strings.append(user_input)

        print("\n✅ Batch Decoding Results:\n")
        for encoded in encoded_strings:
            decoded = decode_rot13(encoded)
            if is_valid_decoded_string(decoded):
                print(f"🔹 Encoded: {encoded} → Decoded: {decoded}")
            else:
                print(f"⚠️ Invalid ROT13 string: {encoded}")
    
    elif choice == "5":
        interactive_mode()
    
    else:
        print("\n⚠️ Invalid choice. Please enter 1, 2, 3, 4, or 5.")

# Run the script
if __name__ == "__main__":
    main()
