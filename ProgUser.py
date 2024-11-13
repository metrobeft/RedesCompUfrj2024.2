import json
import socket
import hashlib
import base64
from cryptography.fernet import Fernet

KEY = base64.urlsafe_b64encode(hashlib.sha256(b'qweasd').digest())
cipher_suite = Fernet(KEY)
MESSAGE_LENGTH_HEADER = 10


def response_is_error(response):
    return 'error' in response


def prompt_for_connection():
    print('Type the server IP:')
    server_ip = input()
    print('Type the server port:')
    server_port = int(input())
    return server_ip, server_port


def prompt_login():
    print('Type the user:')
    user = input()
    print('Type the password:')
    password = input()
    return {
        'User': user,
        'Pass': password,
    }


def send_login_request(user: dict, server_info: tuple):
    request = {
        'Flag': 0,
        'User': user['User'],
        'Pass': user['Pass'],
    }
    return send_request(request, server_info)


def send_creation_request(user: dict, server_info: tuple):
    request = {
        'Flag': 3,
        'User': user['User'],
        'Pass': user['Pass'],
    }
    return send_request(request, server_info)


def send_message_list_request(server_info: tuple):
    request = {
        'Flag': 2,
    }
    return send_request(request, server_info)


def send_message_request(recipient: str, message: str,
                         logged_user: dict, server_info: tuple):
    request = {
        'Flag': 1,
        'User': logged_user['User'],
        'Destinatario': recipient,
        'Mensagem': message,
    }
    return send_request(request, server_info)


def read_message_length(sock: socket.socket) -> int:
    message_length = int(sock.recv(MESSAGE_LENGTH_HEADER).decode().strip())
    return message_length


def send_request(request: dict, server_info: tuple) -> dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(server_info)
            # send
            print(f'Sending request: {request}')
            request_str = json.dumps(request)
            encrypted_data = cipher_suite.encrypt(request_str.encode())
            encrypted_length = f"{len(encrypted_data):<{
                MESSAGE_LENGTH_HEADER}}"
            # Envia o comprimento seguido dos dados criptografados
            to_send = encrypted_length.encode() + encrypted_data
            print(f"Encrypted length: {encrypted_length}")
            print(f"Encrypted data: {encrypted_data}")
            print(f"Data to be sent: {to_send}")
            sock.sendall(encrypted_length.encode() + encrypted_data)
            # receive
            message_length = read_message_length(sock)
            print(f"Message length: {message_length}")
            data = b""
            while len(data) < message_length:
                data += sock.recv(1024)
            print(f"Encrypted response received: {data}")
            response = cipher_suite.decrypt(data).decode()
            response = json.loads(response)
            print('Response received:', response)
            if response_is_error(response):
                print(response)
                exit(1)
            return response
    except ValueError as e:
        # Em caso de erro, retorne a mensagem de erro diretamente
        print({"error": "Erro ao enviar dados"})
        raise e


def print_message_list(message_list):
    for mess in message_list:
        print(mess)


def print_div():
    print('---------------------------------------')


def end_if_error(response):
    if response_is_error(response):
        print_div()
        print('An Error occured')
        print(response)
        print('Exiting...')
        exit(1)


if __name__ == '__main__':
    print_div()
    server_info = prompt_for_connection()
    print('Connected to server.')
    print_div()
    print('1 - Create user')
    print('2 - Login')
    option = input()
    if option == '1':
        print_div()
        print('Creating User...')
        print('Type the user:')
        user = input()
        print('Type the password:')
        password = input()
        response = send_creation_request({'User': user, 'Pass': password},
                                         server_info)
        end_if_error(response)
    elif option != '2':
        print(f'Option: {option} is not supported. Exiting...')
        exit(1)
    print_div()
    logged_user = prompt_login()
    response = send_login_request(logged_user, server_info)
    end_if_error(response)
    print('Login successful. Press Ctrl+C to exit at any moment.')
    while True:
        print_div()
        response = send_message_list_request(server_info)
        print("This is the message list:")
        print_message_list(response['success'])
        print("Send a message? (y/n)")
        print("'n' updates the message list")
        answer = input()
        print_div()
        if answer == 'n':
            continue
        print('Type the reciepient:')
        recipient = input()
        print('Type the message:')
        message = input()
        response = send_message_request(recipient, message,
                                        logged_user, server_info)
        end_if_error(response)
        print(response)
