import tkinter as tk
from tkinter import messagebox
import json
import socket
import hashlib
import base64
from cryptography.fernet import Fernet

# Variáveis globais
User = ""
Pass = ""
IP = ""
PORTA = 0

# Gera uma chave válida de 32 bytes a partir da string 'qweasd' e converte para Base64
KEY = base64.urlsafe_b64encode(hashlib.sha256(b'qweasd').digest())
cipher_suite = Fernet(KEY)

def recv_full_data(sock):
    """Função auxiliar para receber o comprimento da mensagem seguido da mensagem completa."""
    try:
        message_length = int(sock.recv(10).decode().strip())
        data = b""
        while len(data) < message_length:
            data += sock.recv(1024)
        return data
    except ValueError:
        # Em caso de erro, retorne a mensagem de erro diretamente
        return b'{"erro": "Erro ao receber dados"}'

def enviar_dados_criptografados(data, socket):
    """Criptografa e envia o JSON via socket."""
    # Criptografa o JSON
    encrypted_data = cipher_suite.encrypt(data.encode())
    encrypted_length = f"{len(encrypted_data):<10}"
    print("menssagem encriptografada enviada", encrypted_data)
    # Envia o comprimento seguido dos dados criptografados
    socket.sendall(encrypted_length.encode() + encrypted_data)

def envioServer():
    global User, Pass, IP, PORTA
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((IP, PORTA))
            data = json.dumps({"flag": 0, "User": User, "Pass": Pass})
            print("Enviando JSON criptografado para o servidor:", data)  # Debug
            enviar_dados_criptografados(data, s)
            
            # Recebe a resposta completa do servidor e descriptografa
            resposta = recv_full_data(s)
            print("Resposta encriptografada Recebida", resposta)
            resposta = cipher_suite.decrypt(resposta).decode()  # Descriptografa a resposta
            print("Resposta recebida do servidor:", resposta)  # Debug
            resultado = json.loads(resposta)
            
            # Processa o resultado
            if resultado == 0:
                messagebox.showerror("Erro", "A senha digitada está errada")
            elif resultado == 1:
                messagebox.showinfo("Informação", "Não foi possível encontrar um usuário")
            elif isinstance(resultado, dict):  # JSON recebido
                salvar_json(User, resultado)
                exibir_dados(resultado)
        
        except json.JSONDecodeError as e:
            print("Erro ao decodificar JSON recebido:", e)
            messagebox.showerror("Erro de Conexão", f"Erro ao decodificar resposta JSON: {e}")
        except Exception as e:
            print("Erro ao conectar ou receber dados do servidor:", e)  # Sugestão de Teste
            messagebox.showerror("Erro de Conexão", f"Não foi possível conectar ao servidor: {e}")

def criarUsuario():
    """Função para criar um novo usuário"""
    global User, Pass, IP, PORTA
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((IP, PORTA))
            data = json.dumps({"flag": 3, "User": User, "Pass": Pass})
            print("Enviando JSON para criação de usuário criptografado:", data)  # Debug
            enviar_dados_criptografados(data, s)
            
            # Recebe a resposta do servidor e descriptografa
            resposta = recv_full_data(s)
            print("Resposta encriptografada Recebida", resposta)
            resposta = cipher_suite.decrypt(resposta).decode()
            print("Resposta recebida do servidor:", resposta)  # Debug
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
            print("Erro ao conectar ou receber dados do servidor:", e)  # Sugestão de Teste
            messagebox.showerror("Erro de Conexão", f"Não foi possível conectar ao servidor: {e}")

def salvar_json(nome_arquivo, dados_json):
    """Salva o JSON recebido no diretório raiz com o nome do usuário."""
    with open(f"{nome_arquivo}.json", "w") as file:
        json.dump(dados_json, file)

def exibir_dados(dados_json):
    """Atualiza a interface para mostrar os emails em formato personalizado."""
    # Limpa a janela
    for widget in root.winfo_children():
        widget.destroy()
    
    # Label para indicar a seção de emails
    tk.Label(root, text="Emails (não editável)").pack()
    
    # Caixa de texto para exibir os emails em formato personalizado
    json_text = tk.Text(root, height=15, width=50)
    
    # Formatação personalizada dos emails
    if "Email" in dados_json:
        for email in dados_json["Email"]:
            remetente = email.get("id", "Desconhecido")
            mensagem = email.get("Mensagem", "")
            json_text.insert(tk.END, f"Remetente: {remetente}\n")
            json_text.insert(tk.END, f"Mensagem: {mensagem}\n")
            json_text.insert(tk.END, "-" * 30 + "\n\n")
    
    # Configura a caixa de texto para não ser editável
    json_text.config(state="disabled")
    json_text.pack()
    
    # Caixa de texto editável para envio de email
    email_entry = tk.Text(root, height=5, width=50)
    email_entry.pack()
    
    # Botão para enviar o email
    tk.Button(root, text="SendEmail", command=lambda: send_email(email_entry)).pack()
    
    # Botão para atualizar o email
    tk.Button(root, text="Atualizar Email", command=envioServer).pack()

def send_email(email_entry):
    """Função chamada pelo botão SendEmail para enviar o conteúdo do email."""
    conteudo_email = email_entry.get("1.0", tk.END).strip()
    
    if conteudo_email:
        # Janela para inserir o destinatário
        destinatario_window = tk.Toplevel(root)
        destinatario_window.title("Enviar Email")
        
        tk.Label(destinatario_window, text="Digite o nickname do destinatário:").pack()
        destinatario_entry = tk.Entry(destinatario_window)
        destinatario_entry.pack()

        def enviar_para_destinatario():
            destinatario = destinatario_entry.get().strip()
            if not destinatario:
                messagebox.showerror("Erro", "Por favor, insira um destinatário.")
                return
            
            # Envia os dados de email via socket TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.connect((IP, PORTA))
                    data = json.dumps({
                        "flag": 1,
                        "User": User,
                        "destinatario": destinatario,
                        "conteudo_email": conteudo_email
                    })
                    print("Enviando JSON criptografado para o servidor:", data)  # Debug
                    enviar_dados_criptografados(data, s)
                    
                    # Recebe a resposta do servidor e descriptografa
                    resposta = recv_full_data(s)
                    print("Resposta encriptografada Recebida", resposta)
                    resposta = cipher_suite.decrypt(resposta).decode()  # Descriptografa a resposta
                    print("Resposta recebida do servidor:", resposta)  # Debug
                    resultado = json.loads(resposta)
                    
                    if resultado == 0:
                        messagebox.showerror("Erro", "Nickname do destinatário não encontrado.")
                    elif resultado == 1:
                        messagebox.showinfo("Sucesso", "Email enviado com sucesso!")
                    
                    destinatario_window.destroy()
                except json.JSONDecodeError as e:
                    print("Erro ao decodificar JSON recebido:", e)
                    messagebox.showerror("Erro de Conexão", f"Erro ao decodificar resposta JSON: {e}")
                except Exception as e:
                    print("Erro ao conectar ou receber dados do servidor:", e)  # Sugestão de Teste
                    messagebox.showerror("Erro de Conexão", f"Não foi possível conectar ao servidor: {e}")
        
        tk.Button(destinatario_window, text="Enviar", command=enviar_para_destinatario).pack()
    else:
        messagebox.showerror("Erro", "O conteúdo do email não pode estar vazio.")

def enviar():
    """Função de envio quando o botão 'Enviar' é clicado"""
    global User, Pass, IP, PORTA
    User = nickname_entry.get()
    Pass = password_entry.get()
    IP = ip_entry.get()
    PORTA = int(porta_entry.get())
    envioServer()

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
