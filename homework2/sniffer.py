from scapy.all import *
import socket


def get_dns_name(ip_address):
    """Функция для получения DNS-имени по IP-адресу"""
    try:
        # Пробуем получить доменное имя
        dns_name = socket.gethostbyaddr(ip_address)[0]
        return dns_name
    except (socket.herror, socket.gaierror):
        # Если не удалось разрешить имя, возвращаем исходный IP
        return ip_address
    except Exception:
        # На случай других ошибок
        return ip_address


def packet_handler(packet):
    """Функция для анализа пакетов"""

    # Проверяем, есть ли IP слой в пакете
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Получаем DNS-имена для source и destination
        src_dns = get_dns_name(ip_src)
        dst_dns = get_dns_name(ip_dst)

        print(f"IP пакет: {ip_src} ({src_dns}) -> {ip_dst} ({dst_dns}) (протокол: {protocol})")

        # Если это TCP пакет
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"  TCP порты: {sport} -> {dport}")

        # Если это UDP пакет
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"  UDP порты: {sport} -> {dport}")

            # Если это DNS-пакет, покажем DNS-запрос
            if packet.haslayer(DNS) and packet[DNS].qr == 0:  # QR=0 означает запрос
                dns_query = packet[DNSQR].qname.decode('utf-8') if packet.haslayer(DNSQR) else "N/A"
                print(f"  DNS запрос: {dns_query}")

        print("-" * 40)


# Запускаем перехват на 10 пакетов
print("🚀 Начинаю перехват трафика...")

# Захватываем только 10 пакетов для примера
sniff(count=10, prn=packet_handler)

print("✅ Перехват завершен!")