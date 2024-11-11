import json
import os
import socket
import re
import base64
import hashlib
from cryptography.fernet import Fernet

# Gera uma chave válida de 32 bytes a partir da string 'qweasd' e converte para Base64
KEY = base64.urlsafe_b64encode(hashlib.sha256(b'qweasd').digest())
cipher_suite = Fernet(KEY)

def verificar_nickname(nickname):
    """Verifica se o nickname contém apenas letras minúsculas e números, sem espaços ou caracteres especiais."""
    return bool(re.match("^[a-z0-9]+$", nickname))

def criar_usuario(nickname, senha):
    """Cria um usuário com o nickname e senha fornecidos, verificando se o usuário já existe."""
    # Verifica se o nickname é válido
    if not verificar_nickname(nickname):
        return 0  # Usuário inválido

    # Caminho da pasta 'id'
    caminho_pasta = os.path.join(os.getcwd(), "id")
    
    # Cria a pasta 'id' se não existir
    if not os.path.exists(caminho_pasta):
        os.makedirs(caminho_pasta)
    
    # Verifica se o usuário já existe
    caminho_arquivo = os.path.join(caminho_pasta, f"{nickname}.json")
    if os.path.isfile(caminho_arquivo):
        return 3  # Usuário já existe
    
    # Criação do arquivo JSON para o usuário
    dados_usuario = {
        "User": nickname,
        "Pass": senha
    }
    
    with open(caminho_arquivo, "w") as arquivo_json:
        json.dump(dados_usuario, arquivo_json)
    
    return 1  # Usuário criado com sucesso

def Recebimento(user, password, flag, *args):
    if flag == 0:
        caminho_arquivo = os.path.join("id", f"{user}.json")
        if not os.path.isfile(caminho_arquivo):
            return 1
        with open(caminho_arquivo, "r") as file:
            dados_usuario = json.load(file)
            if dados_usuario.get("User") != user or dados_usuario.get("Pass") != password:
                return 0
        return dados_usuario

    elif flag == 1:
        remetente, destinatario, conteudo_email = user, args[0], args[1]
        caminho_arquivo = os.path.join("id", f"{destinatario}.json")
        if not os.path.isfile(caminho_arquivo):
            return 0
        with open(caminho_arquivo, "r") as file:
            dados_destinatario = json.load(file)
        nova_mensagem = {
            "id": remetente,
            "Mensagem": conteudo_email
        }
        if "Email" in dados_destinatario:
            dados_destinatario["Email"].append(nova_mensagem)
        else:
            dados_destinatario["Email"] = [nova_mensagem]
        with open(caminho_arquivo, "w") as file:
            json.dump(dados_destinatario, file, indent=4)
        return 1

    elif flag == 3:
        nickname = user
        senha = password
        return criar_usuario(nickname, senha)

    return None

def start_server():
    HOST = '0.0.0.0'
    PORT = 7444
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        
        while True:
            conn, addr = server_socket.accept()
            with conn:
                try:
                    # Recebe o comprimento da mensagem
                    encrypted_length = int(conn.recv(10).decode().strip())
                    encrypted_data = conn.recv(encrypted_length)
                    
                    # Descriptografa os dados recebidos
                    data = cipher_suite.decrypt(encrypted_data).decode()
                    request = json.loads(data)
                    
                    flag = request.get("flag")
                    
                    if flag == 0:
                        user = request.get("User")
                        password = request.get("Pass")
                        response = Recebimento(user, password, flag)
                    elif flag == 1:
                        user = request.get("User")
                        destinatario = request.get("destinatario")
                        conteudo_email = request.get("conteudo_email")
                        response = Recebimento(user, None, flag, destinatario, conteudo_email)
                    elif flag == 3:
                        user = request.get("User")
                        password = request.get("Pass")
                        response = Recebimento(user, password, flag)
                    else:
                        response = {"erro": "Flag inválido"}
                    
                    # Serializa a resposta e criptografa antes de enviar
                    response_data = json.dumps(response)
                    encrypted_response = cipher_suite.encrypt(response_data.encode())
                    response_length = f"{len(encrypted_response):<10}"
                    conn.sendall(response_length.encode() + encrypted_response)
                
                except json.JSONDecodeError:
                    error_response = {"erro": "Dados inválidos"}
                    encrypted_error = cipher_suite.encrypt(json.dumps(error_response).encode())
                    conn.sendall(f"{len(encrypted_error):<10}".encode() + encrypted_error)
                except Exception:
                    error_response = {"erro": "Erro interno do servidor"}
                    encrypted_error = cipher_suite.encrypt(json.dumps(error_response).encode())
                    conn.sendall(f"{len(encrypted_error):<10}".encode() + encrypted_error)

if __name__ == "__main__":
    start_server()
