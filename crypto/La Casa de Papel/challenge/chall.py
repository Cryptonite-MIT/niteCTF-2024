import hashlib
import base64
import pyfiglet


def secret():
    return "ZFPCkO5hgllij9iVSkbeq"  # Length = 21


def md5(secret, msg):
    hash = hashlib.md5(secret + msg).hexdigest().encode()
    return base64.b64encode(hash).decode()


def menu(secret):
    while True:
        print("\n1. Practice Convo")
        print("2. Let's Fool Alice!")
        print("3. Crack the Vault")
        print("4. Exit")
        try:
            choice = input("Choose an option: ")
        except EOFError:
            exit(0)
        if choice == '1':
            practice_convo(secret)
        elif choice == '2':
            fool_alice(secret)
        elif choice == '3':
            crack_the_vault()
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


def practice_convo(secret):
    try:
        message = input("Send a message: ")
    except EOFError:
        exit(0)
    hash = md5(secret, message.encode('latin-1'))
    print(f"Here is your encrypted message: {hash}")


def fool_alice(secret):
    print("\nBot: Okay, let's see if you're the real deal. What's your name?")
    try:
        user_name = input("Your name: ").encode('latin-1')
    except EOFError:
        exit(0)
    user_name = user_name.decode('unicode_escape').encode('latin-1')
    print("\nBot: Please provide your HMAC")
    try:
        user_hmac = input("Your HMAC: ").encode('latin-1')
    except EOFError:
        exit(0)

    if b"Bob" in user_name:
        hash = base64.b64decode(md5(secret, user_name))
        if user_hmac == hash:
            print("\nAlice: Oh hey Bob! Here is the vault code you wanted:")
            with open('secret.txt', 'r') as file:
                secret_content = file.read()
                print(secret_content)
        else:
            print("\nAlice: LIARRRRRRR!!")
    else:
        print("\nAlice: IMPOSTERRRR")


def crack_the_vault():
    print("\nVault Person: Enter password")
    try:
        passs = input("Password: ")
    except EOFError:
        exit(0)

    with open('secret.txt', 'r') as file:
        secret_content = file.read().strip()
        if passs == secret_content:
            with open('flag.txt', 'r') as flag_file:
                flag_content = flag_file.read().strip()
                print(f"\nVault Unlocked! The flag is: {flag_content}")
        else:
            print("Incorrect password!")


if __name__ == "__main__":
    secret_key = secret().encode()
    ascii_art = pyfiglet.figlet_format("La Casa de Papel")
    print(ascii_art)
    menu(secret_key)
