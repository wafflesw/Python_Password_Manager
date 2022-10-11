import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def write_key(password): #creates a password bases on the user input on masterpwd
    salt = b'\xbf\x80&i\xba5\xc3\x83O8\x82\x83\xcd\x84L\x9f' #determined in salt function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    ) #above are simple perameters used to creating the encryption key
    password = password.encode() #changes password to bits
    key = base64.urlsafe_b64encode(kdf.derive(password)) #creates actual encrpytion key
    if(b'SMp6IaKAI68TkVUqKgsfVi_0uOzLtAkjBSI43ghNpwE=' != key):#compares for correct password
        return 0
    f = Fernet(key)
    return f

def salt(): #this function isn't used outside the first creation of the salt variable in write_key
    salt = os.urandom(16)
    print(salt)

def add(username,password,platform,fern): #used to add information to the file
    password = encry(password,fern)
    with open('password.txt', 'a') as f:
        f.write(platform + ":" + username + ":" + password + "\n")

def update(username,password,platform,fern,newName): #creates a new file in order to update any information the user
    #requires while deleteing the orginal password.txt and substituiting it for the new one
    flag = False
    newFile = open("temp.txt", 'w')
    with open('password.txt', 'r') as f:
        for line in f.readlines():
            info = line.strip() #used to strip the string of the \n
            infosplit = info.split(":") #looks for the info splits built in
            if(len(infosplit) > 0): #to counteract the endoffile the is passed at the end
                if infosplit[0] == platform: #checks for correct platform to update informaiton else just write current info
                    password = encry(password,fern)
                    newFile.write(newName + ":" + username + ":" + password + "\n")
                    flag = True
                else:
                    newFile.write(line)
    newFile.close()
    os.remove("password.txt") #these two line swap delete and replace the old file
    os.rename("temp.txt","password.txt")
    return flag

def viewall(fern): #simple function that allows the user to view all info in the password document
    with open('password.txt', 'r') as f:
        for line in f.readlines():
            info = line.strip()
            platform, username, password = info.split(":")
            password = decry(password,fern)
            print(platform + "|" + "Username:" + username + ", Password:" + password + "\n")

def encry(pwd,fern): #used to encrypt the password passed to it
    encpwd = fern.encrypt(pwd.encode()).decode()
    return encpwd

def decry(pwd,fern): #used to decrypt any password on the document
    decpwd = fern.decrypt(pwd.encode()).decode()
    return decpwd

masterpwd = input("please enter password:")# password is Island is casse sensitive
fern = write_key(masterpwd)
if fern == 0:
    #this was created to prevent any password being used to to create a key which would result in the creation of multiple
    #different encrypted password using different keys that could cause confusion when attempting to view all
    print("incorrect password please try run again")
    exit(0)
while True:
    select = input("would you like to view, add, or update a password?(add, view, update, q):")
    #uses add view update and q as instructed above
    if(select == "q"):#simple quit answer to allow a form of exit
        break
    if(select == "add"): #obtains user informaiton to input into the password manager
        plat = input("Please specify what platform this is for:")
        uName = input("please input desired username:")
        pWord = input("please input desired password:")
        add(uName,pWord,plat,fern)
        print("information has been stored")
    elif(select == "view"):#used to view information
        viewall(fern)
    elif(select == "update"):#used to update information and cannot be used as a delete as it will just cause an empty
        #Username with an encrypted NULL
        plat = input("Enter the platform credentials you are updating:")
        uName = input("Enter the new username:")
        pWord = input("Enter the new password:")
        chgPlatName = input("Would you like to rename the platform containing this information?(y/n):")
        if(chgPlatName == 'y'):
            newName = input("please enter new platform name:")
        else:
            newName = plat
        chgFound = update(uName,pWord,plat,fern,newName)
        if(chgFound == False):
            print('\n'+"No change was found please make sure spelling and capitalization was correct")
        else:
            print('\n'+"Changes to " + newName + " were made")

