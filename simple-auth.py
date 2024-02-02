import bcrypt

def encryptString(usrString, salt=None):
    bytes = usrString.encode('utf-8')
    if not salt:
        salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)
    return [hash,salt]

def register():
    username = ""
    passwd = ""

    username = input("Username: ")
    passwd = input("Password: ")

    hashedPasswd = encryptString(passwd)
    hash = hashedPasswd[0]
    salt = hashedPasswd[1]
    
    f = open("users", mode="a")
    f.write(username)
    f.write("\n")
    f.close()

    f = open("hashes", mode="ab")
    f.write(hash)
    f.close()
    f = open("hashes", mode="a")
    f.write("\n")
    f.close()

    f = open("salts", mode="ab")
    f.write(salt)
    f.close()
    f = open("salts", mode="a")
    f.write("\n")
    f.close()
    
    return 0

def login():
    username = ""
    passwd = ""

    username = input("Username: ")
    passwd = input("Password: ")

    f = open("users", "r")
    users = f.readlines()
    f.close()

    index = -1
    i = 0
    for user in users:
        if username == user.strip():
            index = i
        i += 1
    if index == -1:
        print("User does not exist")
        return 0

    f = open("salts", mode="rb")
    salts = f.readlines()
    f.close()
    salt = salts[index]

    f = open("hashes", mode="rb")
    hashes = f.readlines()
    f.close()
    oldHash = hashes[index].strip()

    newHash = encryptString(passwd, salt)[0]

    if oldHash == newHash:
        print("Login successful")
    else:
        print("Login failed")

    return 0

def main():
    mode = input("Enter l for login, r for register: ")
    if mode == "l":
        login()
    elif mode == "r":
        register()
    return 0

if __name__ == "__main__":
    main()
