import tkinter as tk
from tkinter import messagebox
import json
import socket
import base64
import hashlib
from cryptography.fernet import Fernet

# Configuração de criptografia
KEY = base64.urlsafe_b64encode(hashlib.sha256(b'qweasd').digest())
cipher_suite = Fernet(KEY)

# Variáveis globais
User = ""
Pass = ""
IP = ""
PORTA = 0
conversas_abertas = {}  # Dicionário para janelas de chat abertas
dados_json = {}  # Dicionário para armazenar o JSON inicial recebido do servidor

def recv_full_data(sock):
    """Função auxiliar para receber o comprimento da mensagem seguido da mensagem completa."""
    try:
        message_length = int(sock.recv(10).decode().strip())
        data = b""
        while len(data) < message_length:
            data += sock.recv(1024)
        return data
    except ValueError:
        return b'{"erro": "Erro ao receber dados"}'

def enviar_dados_criptografados(data, socket):
    """Criptografa e envia o JSON via socket."""
    encrypted_data = cipher_suite.encrypt(data.encode())
    encrypted_length = f"{len(encrypted_data):<10}"
    socket.sendall(encrypted_length.encode() + encrypted_data)

def envioServer():
    """Função para envio inicial de dados de login."""
    global User, Pass, IP, PORTA
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((IP, PORTA))
            data = json.dumps({"flag": 0, "User": User, "Pass": Pass})
            enviar_dados_criptografados(data, s)
            
            # Recebe a resposta completa do servidor e descriptografa
            resposta = recv_full_data(s)
            resposta = cipher_suite.decrypt(resposta).decode()
            resultado = json.loads(resposta)
            
            # Processa o resultado
            if resultado == 0:
                messagebox.showerror("Erro", "A senha digitada está errada")
            elif resultado == 1:
                messagebox.showinfo("Informação", "Não foi possível encontrar um usuário")
            elif isinstance(resultado, dict):  # JSON recebido
                global dados_json
                dados_json = resultado  # Armazena o JSON para uso posterior
                exibir_chat_interface()
        
        except json.JSONDecodeError as e:
            print("Erro ao decodificar JSON recebido:", e)
            messagebox.showerror("Erro de Conexão", f"Erro ao decodificar resposta JSON: {e}")
        except Exception as e:
            print("Erro ao conectar ou receber dados do servidor:", e)
            messagebox.showerror("Erro de Conexão", f"Não foi possível conectar ao servidor: {e}")

def envioCriarUsuario():
    """Função para criar um novo usuário."""
    global User, Pass, IP, PORTA
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((IP, PORTA))
            data = json.dumps({"flag": 3, "User": User, "Pass": Pass})
            enviar_dados_criptografados(data, s)
            
            # Recebe a resposta do servidor e descriptografa
            resposta = recv_full_data(s)
            resposta = cipher_suite.decrypt(resposta).decode()
            resultado = json.loads(resposta)
            
            # Processa o resultado
            if resultado == 0:
                messagebox.showerror("Erro", "Usuário inválido")
            elif resultado == 1:
                messagebox.showinfo("Sucesso", "Usuário criado com sucesso!")
            elif resultado == 3:
                messagebox.showinfo("Erro", "Usuário já existe")
        
        except json.JSONDecodeError as e:
            print("Erro ao decodificar JSON recebido:", e)
            messagebox.showerror("Erro de Conexão", f"Erro ao decodificar resposta JSON: {e}")
        except Exception as e:
            print("Erro ao conectar ou receber dados do servidor:", e)
            messagebox.showerror("Erro de Conexão", f"Não foi possível conectar ao servidor: {e}")

def exibir_chat_interface():
    """Exibe a interface de chat após o login."""
    # Limpa a janela de login
    for widget in root.winfo_children():
        widget.destroy()
    
    # Lista de IDs únicos de remetentes no JSON
    ids_unicos = set(email["id"] for email in dados_json.get("Email", []))
    
    # Exibir a lista de IDs únicos como botões para abrir conversas
    tk.Label(root, text="Conversas Abertas:").pack()
    for usuario_id in ids_unicos:
        tk.Button(root, text=usuario_id, command=lambda u=usuario_id: abrir_conversa(u)).pack()

    # Botão para iniciar nova conversa
    tk.Button(root, text="Criar Nova Conversa", command=criar_conversa).pack()

def abrir_conversa(usuario):
    """Abre uma nova janela de conversa com um usuário específico."""
    if usuario in conversas_abertas:
        return  # Evita abrir janelas duplicadas para o mesmo usuário

    janela_chat = tk.Toplevel(root)
    janela_chat.title(f"Conversa com {usuario}")

    # Define o que acontece ao fechar a janela
    def fechar_janela():
        janela_chat.destroy()
        if usuario in conversas_abertas:
            del conversas_abertas[usuario]

    janela_chat.protocol("WM_DELETE_WINDOW", fechar_janela)

    # Área de exibição de mensagens
    chat_text = tk.Text(janela_chat, height=15, width=50, state="disabled")
    chat_text.pack()

    # Botão para atualizar mensagens
    tk.Button(janela_chat, text="Atualizar", command=lambda: atualizar_mensagens(usuario, chat_text)).pack()

    # Caixa de entrada de mensagem
    msg_entry = tk.Entry(janela_chat, width=50)
    msg_entry.pack()

    # Botão de enviar mensagem
    tk.Button(janela_chat, text="Enviar", command=lambda: enviar_mensagem(usuario, msg_entry)).pack()

    conversas_abertas[usuario] = (janela_chat, chat_text)

    # Carregar todas as mensagens anteriores do JSON e exibir
    atualizar_mensagens(usuario, chat_text)

def atualizar_mensagens(usuario, chat_text):
    """Atualiza as mensagens para um usuário específico ao clicar no botão de atualização."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((IP, PORTA))
            data = json.dumps({"flag": 0, "User": User, "Pass": Pass})  # Solicita as mensagens do usuário
            enviar_dados_criptografados(data, s)
            resposta = recv_full_data(s)
            resposta = cipher_suite.decrypt(resposta).decode()
            mensagens = json.loads(resposta).get("Email", [])

            chat_text.config(state="normal")
            chat_text.delete("1.0", tk.END)  # Limpa a caixa de texto antes de adicionar novas mensagens

            for email in mensagens:
                if email["id"] == usuario:
                    remetente = email["id"]
                    conteudo = email.get("Mensagem", "")
                    chat_text.insert(tk.END, f"{remetente}: {conteudo}\n")
            chat_text.config(state="disabled")
            chat_text.yview(tk.END)
        except Exception as e:
            print("Erro ao atualizar mensagens:", e)

def enviar_mensagem(usuario, msg_entry, msg_padrao=None):
    """Envia mensagem para o usuário específico."""
    conteudo_msg = msg_padrao or msg_entry.get().strip()
    if conteudo_msg:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((IP, PORTA))
            data = json.dumps({
                "flag": 1,
                "User": User,
                "destinatario": usuario,
                "conteudo_email": conteudo_msg
            })
            enviar_dados_criptografados(data, s)
            resposta = recv_full_data(s)
            resposta = cipher_suite.decrypt(resposta).decode()
            resultado = json.loads(resposta)

            # Exibir mensagem enviada na janela de chat
            if usuario in conversas_abertas:
                chat_text = conversas_abertas[usuario][1]
                chat_text.config(state="normal")
                chat_text.insert(tk.END, f"Você: {conteudo_msg}\n")
                chat_text.config(state="disabled")
                chat_text.yview(tk.END)  # Rolagem automática para a última mensagem

            if msg_padrao is None:
                msg_entry.delete(0, tk.END)

def criar_conversa():
    """Abre uma janela para inserir o nickname do usuário para iniciar uma nova conversa."""
    nova_conversa = tk.Toplevel(root)
    nova_conversa.title("Nova Conversa")
    
    tk.Label(nova_conversa, text="Digite o nickname do usuário:").pack()
    usuario_entry = tk.Entry(nova_conversa)
    usuario_entry.pack()

    def iniciar_conversa():
        usuario = usuario_entry.get().strip()
        if usuario:
            abrir_conversa(usuario)
            nova_conversa.destroy()

    tk.Button(nova_conversa, text="Iniciar", command=iniciar_conversa).pack()

def enviar():
    """Função de envio quando o botão 'Enviar' é clicado."""
    global User, Pass, IP, PORTA
    User = nickname_entry.get()
    Pass = password_entry.get()
    IP = ip_entry.get()
    PORTA = int(porta_entry.get())
    envioServer()
    
def criarUsuario():
    """Função de envio quando o botão 'Enviar' é clicado."""
    global User, Pass, IP, PORTA
    User = nickname_entry.get()
    Pass = password_entry.get()
    IP = ip_entry.get()
    PORTA = int(porta_entry.get())
    envioCriarUsuario()

# Interface gráfica
root = tk.Tk()
root.title("Login")

# Campos para usuário e senha
tk.Label(root, text="Nickname").pack()
nickname_entry = tk.Entry(root)
nickname_entry.pack()

tk.Label(root, text="Password").pack()
password_entry = tk.Entry(root, show="*")
password_entry.pack()

# Campos para IP e Porta
tk.Label(root, text="IP").pack()
ip_entry = tk.Entry(root)
ip_entry.pack()

tk.Label(root, text="Porta").pack()
porta_entry = tk.Entry(root)
porta_entry.pack()

# Botões para iniciar a comunicação e criar usuário
tk.Button(root, text="Enviar", command=enviar).pack()
tk.Button(root, text="Criar Usuário", command=criarUsuario).pack()

root.mainloop()
