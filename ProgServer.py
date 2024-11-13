import json
import os
import socket
import re
import base64
import hashlib
from cryptography.fernet import Fernet
from pathlib import Path
from argparse import ArgumentParser
import traceback

# Gera uma chave válida de 32 bytes a partir da string 'qweasd'
# e converte para Base64
KEY = base64.urlsafe_b64encode(hashlib.sha256(b'qweasd').digest())
cipher_suite = Fernet(KEY)
logged_user = {}
user_dir = Path(os.getcwd(), 'id')
MESSAGE_LENGTH_HEADER = 10


def user_valido(nickname):
    """Verifica se o nickname contém apenas letras minúsculas e números,
    sem espaços ou caracteres especiais."""
    return bool(re.match("^[a-z0-9]+$", nickname))


def process_request_flag_0(request: dict) -> dict:
    """
    Processes a request with flag 0.

    Parameters
    ----------
    request : dict
        Received request.

    Returns
    -------
    dict
        Generated response.
    """
    global logged_user
    user = request.get("User")
    password = request.get("Pass")
    user_file = user_dir / f"{user}.json"
    with user_file.open('r') as file:
        user_data = json.load(file)
    if user_data.get("User") != user or user_data.get("Pass") != password:
        return {"error": "usuario ou senha invalida"}
    else:
        logged_user = user_data
        return user_data


def process_request_flag_1(request: dict) -> dict:
    """
    Processes a request with flag 1.

    Parameters
    ----------
    request : dict
        Received request.

    Returns
    -------
    dict
        Generated response.
    """
    global logged_user
    if not logged_user:
        return {"error": "usuario nao esta logado"}
    remetente = logged_user.get("User")
    destinatario = request.get("Destinatario")
    conteudo_email = request.get("Mensagem")
    destinatario_file = Path("id", f"{destinatario}.json")
    if not destinatario_file.exists():
        return {"error": "destinatario nao existe"}
    with destinatario_file.open("r") as file:
        destinatario_data = json.load(file)
    nova_mensagem = {
        "id": remetente,
        "Mensagem": conteudo_email
    }
    if "Email" in destinatario_data:
        destinatario_data["Email"].append(nova_mensagem)
    else:
        destinatario_data["Email"] = [nova_mensagem]
    with destinatario_file.open('w') as file:
        json.dump(destinatario_data, file, indent=4)
    return {"success": "mensagem enviada com sucesso"}


def process_request_flag_2(request: dict) -> dict:
    """
    Processes a request with flag 2.

    Parameters
    ----------
    request : dict
        Received request.

    Returns
    -------
    dict
        Generated response.
    """
    global logged_user
    if not logged_user:
        return {"error": "usuario nao esta logado"}
    user_file = Path("id", f"{logged_user.get('User')}.json")
    with user_file.open("r") as file:
        user_data = json.load(file)
    if "Email" in user_data:
        return {"success": user_data["Email"]}
    else:
        return {"success": []}


def process_request_flag_3(request: dict) -> dict:
    """
    Processes a request with flag 3.

    Parameters
    ----------
    request : dict
        Received request.

    Returns
    -------
    dict
        Generated response.
    """
    user = request.get("User")
    senha = request.get("Pass")
    # Verifica se o user é válido
    if not user_valido(user):
        return {"error": "usuario invalido"}

    # Cria a pasta 'id' se não existir
    user_dir.mkdir(exist_ok=True, parents=True)

    user_file = user_dir / f"{user}.json"
    if user_file.exists():
        return {"error": "usuario ja existe"}

    # Criação do arquivo JSON para o usuário
    dados_usuario = {
        "User": user,
        "Pass": senha
    }

    with user_file.open("w") as json_file:
        json.dump(dados_usuario, json_file)

    return {"success": "usuario criado com sucesso"}


def get_request(conn: socket) -> dict:
    """
    Listens to a new request and decypts it.

    Parameters
    ----------
    conn : socket
        Socket to listen to

    Returns
    -------
    dict
        The new request
    """
    encrypted_length = int(conn.recv(MESSAGE_LENGTH_HEADER).decode().strip())
    encrypted_data = conn.recv(encrypted_length)
    print(f'Encypted request received: {encrypted_data}')
    # Decrypt the data received
    data = cipher_suite.decrypt(encrypted_data).decode()
    request = json.loads(data)
    print(f'Request received: {request}')
    return request


def send_response(conn: socket, response: dict):
    """
    Encrypts a response and sends it through the socket

    Parameters
    ----------
    conn : socket
        Socket to send the response
    response : dict
        The response to send
    """
    # Serializa a resposta e criptografa antes de enviar
    response_data = json.dumps(response)
    print(f'Response to be sent: {response_data}')
    encrypted_response = cipher_suite.encrypt(
        response_data.encode())
    response_length = f"{len(encrypted_response):<{MESSAGE_LENGTH_HEADER}}"
    print(f'Encrypted response to be sent: {encrypted_response}')
    print(f'Response length to be sent: {response_length}')
    to_send = response_length.encode() + encrypted_response
    print(f'Data to be sent: {to_send}')
    conn.sendall(to_send)


REQUEST_HANDLERS = {
    0: process_request_flag_0,   # Login
    1: process_request_flag_1,   # Send Message
    2: process_request_flag_2,   # Message List
    3: process_request_flag_3    # Create User
}


def start_server(host, port):
    """
    Runs the main server loop
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print('Listening on', (host, port))

        while True:
            conn, _ = server_socket.accept()
            with conn:
                try:
                    request = get_request(conn)
                    flag = request.get("Flag")
                    print(flag)
                    response = REQUEST_HANDLERS[flag](request)
                    send_response(conn, response)
                except KeyError:
                    response = {"erro": "Flag invalido"}
                    send_response(conn, response)
                except json.JSONDecodeError:
                    response = {"erro": "JSON invalido"}
                    send_response(conn, response)
                except InterruptedError:
                    print('Conexão interrompida')
                except Exception:
                    response = {"erro": "Erro interno do servidor"}
                    send_response(conn, response)
                    print(traceback.format_exc())


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1', type=str)
    parser.add_argument('--port', default=5000, type=int)
    args = parser.parse_args()
    start_server(args.host, args.port)
