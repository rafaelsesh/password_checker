import hashlib
import requests

def check_password(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # Faz a requisição à API
    response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
    
    if response.status_code == 200:
        hashes = response.text.splitlines()
        for hash_line in hashes:
            hash_suffix, count = hash_line.split(':')
            if hash_suffix == suffix:
                return (
                    f'Senha comprometida! Encontrada {count} vezes em data breaches.\n'
                    'Para mais detalhes sobre segurança e para verificar se sua senha está comprometida, visite:\n'
                    '1. [Pwned Passwords - Data Breach Details](https://haveibeenpwned.com/Passwords)'
                )
        return 'Senha não encontrada em data breaches.'
    else:
        return 'Erro ao consultar a API.'

if __name__ == "__main__":
    password = input('Digite a senha para verificar: ')
    print(check_password(password))
