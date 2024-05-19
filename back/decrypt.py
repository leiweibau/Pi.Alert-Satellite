import subprocess, json

password = "password"  # Hier das tatsächliche Passwort einfügen

openssl_command = [
    "openssl", "enc", "-d", "-aes-256-cbc", "-in", "encrypted_scandata",
    "-pbkdf2", "-pass", "pass:{}".format(password)
]

with subprocess.Popen(openssl_command, stdout=subprocess.PIPE) as proc:
    decrypted_data = proc.stdout.read()

decrypted_dict = json.loads(decrypted_data.decode('utf-8'))

with open('decrypted.json', 'w') as outfile:
    json.dump(decrypted_dict, outfile, indent=4)

print(decrypted_dict)
