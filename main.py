import pcap
import dpkt
from collections import defaultdict
import time

# Limite de tráfego por IP em bytes por segundo
limite_trafego_por_ip = 100000  # 100 KB/s

# Dicionário para rastrear o tráfego por IP
trafego_por_ip = defaultdict(int)

# Função para verificar o tráfego por IP e detectar um possível ataque
def detectar_ddos(ip):
    trafego_total = sum(trafego_por_ip.values())
    if trafego_total > limite_trafego_por_ip:
        print(f"Alerta de possível ataque DDoS! Tráfego total: {trafego_total} bytes")
        print("Endereços IP suspeitos:")
        for end_ip, trafego in trafego_por_ip.items():
            if trafego > limite_trafego_por_ip:
                print(f"IP: {end_ip}, Tráfego: {trafego} bytes")
        # Aqui você pode implementar medidas de mitigação, como bloqueio de IP ou redirecionamento.

# Função para extrair o endereço IP de um pacote Ethernet
def extract_ip_address(packet):
    eth = dpkt.ethernet.Ethernet(packet)
    if isinstance(eth.data, dpkt.ip.IP):
        return eth.data.src  # Retorna o endereço IP de origem

# Abre uma interface de rede para captura
pc = pcap.pcap()

for _, packet in pc:
    ip = extract_ip_address(packet)
    if ip:
        tamanho_pacote = len(packet)
        trafego_por_ip[ip] += tamanho_pacote

        # Verifica o tráfego a cada segundo
        if time.time() - pc.stats()[2] >= 1:
            detectar_ddos(ip)
            # Limpa o tráfego a cada segundo
            trafego_por_ip.clear()
