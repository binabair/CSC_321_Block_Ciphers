fileName = "my_secret_message.txt"

try:
    f = open(fileName, "r")
    text = f.read()
    print(text)
except FileNotFoundError:
    print("File not found")
