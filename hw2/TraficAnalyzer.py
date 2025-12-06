from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import json
import webbrowser
import time


class HTTPTrafficAnalyzer:
    def __init__(self):
        self.sessions = {}
        self.http_requests = []
        self.http_responses = []

    def analyze_packet(self, packet):
        # Анализ HTTP запросов
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            request_info = {
                'timestamp': time.time(),
                'method': http_layer.Method.decode(),
                'host': http_layer.Host.decode() if http_layer.Host else '',
                'path': http_layer.Path.decode(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'user_agent': http_layer.get_field('User-Agent').decode() if http_layer.get_field('User-Agent') else '',
                'headers': dict(http_layer.fields)
            }
            self.http_requests.append(request_info)
            print(f"HTTP Request: {request_info['method']} {request_info['path']}")

        # Анализ HTTP ответов
        if packet.haslayer(HTTPResponse):
            http_layer = packet[HTTPResponse]
            response_info = {
                'timestamp': time.time(),
                'status_code': http_layer.Status_Code.decode() if http_layer.Status_Code else '',
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'headers': dict(http_layer.fields)
            }
            self.http_responses.append(response_info)
            print(f"HTTP Response: Status {response_info['status_code']}")

    def start_analysis(self):
        print("Запуск анализа HTTP трафика...")
        sniff(prn=self.analyze_packet, store=0,
              filter="tcp port 80 or tcp port 443")

    def generate_report(self):
        print("\n" + "=" * 50)
        print("ОТЧЕТ ПО АНАЛИЗУ ТРАФИКА")
        print("=" * 50)

        print(f"\nВсего HTTP запросов: {len(self.http_requests)}")
        print(f"Всего HTTP ответов: {len(self.http_responses)}")

        print("\nДЕТАЛИ ЗАПРОСОВ:")
        for i, req in enumerate(self.http_requests, 1):
            print(f"{i}. {req['method']} {req['path']} -> {req['dst_ip']}")

        print("\nСТАТУСЫ ОТВЕТОВ:")
        status_counts = {}
        for resp in self.http_responses:
            status = resp['status_code']
            status_counts[status] = status_counts.get(status, 0) + 1

        for status, count in status_counts.items():
            print(f"Статус {status}: {count} раз")


# Запуск анализатора
analyzer = HTTPTrafficAnalyzer()

# Запуск в отдельном потоке
import threading

analysis_thread = threading.Thread(target=analyzer.start_analysis)
analysis_thread.daemon = True
analysis_thread.start()



# Открываем Gruyere
webbrowser.open("http://localhost:8008")

# Даем время для взаимодействия
print("Взаимодействуйте с сайтом в течение 60 секунд...")
time.sleep(60)

# Генерируем отчет
analyzer.generate_report()