import time
import threading
from collections import defaultdict, deque
from scapy.all import sniff, TCP, Raw, IP

class RudyAnalyzer:
    """
    Анализатор R.U.D.Y. атак (slow HTTP POST).
    Захватывает TCP пакеты на порту 80/443 (HTTP/HTTPS надо отдельно),
    отслеживает медленные POST-запросы и выдает метрики.

    Метрики:
    - IP атакующего
    - Продолжительность соединения
    - Объем переданных данных
    - Статус (подозрительно, подтверждено)
    """

    def __init__(self, iface=None, port=80, max_connections=1000, slow_threshold_sec=30, min_data_bytes=1024):
        """
        :param iface: сетевой интерфейс (None - авто)
        :param port: порт для мониторинга (обычно 80 для HTTP)
        :param max_connections: максимальное число отслеживаемых соединений
        :param slow_threshold_sec: порог времени для медленной передачи
        :param min_data_bytes: минимальный объем данных для "быстрого" соединения
        """
        self.iface = iface
        self.port = port
        self.max_connections = max_connections
        self.slow_threshold_sec = slow_threshold_sec
        self.min_data_bytes = min_data_bytes

        # Хранилище: conn_id -> info
        # conn_id: (src_ip, src_port, dst_ip, dst_port)
        # info: dict с ключами start, last, data_len, status
        self.connections = {}
        self.lock = threading.Lock()

        # Очередь событий для передачи в GUI или лог
        self.events = deque(maxlen=500)

        self.running = False
        self.sniffer_thread = None

    def start(self):
        """Запустить сниффер в отдельном потоке"""
        if self.running:
            return
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        """Остановить сниффер"""
        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)

    def _sniff_loop(self):
        sniff(filter=f"tcp port {self.port}", prn=self._packet_callback, store=False, iface=self.iface, stop_filter=self._stop_filter)

    def _stop_filter(self, pkt):
        return not self.running

    def _packet_callback(self, pkt):
        if not pkt.haslayer(TCP):
            return
        tcp = pkt[TCP]
        ip = pkt[IP]

        conn_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
        now = time.time()

        # Обрабатываем пакеты с данными (Raw)
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load

            with self.lock:
                info = self.connections.get(conn_id)
                # Новый POST запрос (начинается с b"POST ")
                if raw.startswith(b"POST "):
                    # Начинаем отслеживание нового соединения
                    self.connections[conn_id] = {
                        "start": now,
                        "last": now,
                        "data_len": len(raw),
                        "status": "open",
                        "ip": ip.src
                    }
                elif info:
                    # Обновляем состояние соединения
                    info["last"] = now
                    info["data_len"] += len(raw)

                    duration = now - info["start"]
                    data_len = info["data_len"]

                    # Проверяем медленное соединение (RUDY)
                    if duration > self.slow_threshold_sec and data_len < self.min_data_bytes:
                        if info["status"] != "rudy_detected":
                            info["status"] = "rudy_detected"
                            event = {
                                "ip": ip.src,
                                "duration_sec": round(duration, 1),
                                "data_len": data_len,
                                "timestamp": now,
                                "desc": f"R.U.D.Y. attack suspected: duration={duration:.1f}s, data={data_len} bytes"
                            }
                            self._add_event(event)
                else:
                    # Не отслеживаем это соединение, возможно не POST начало
                    pass

        # Убираем старые соединения, которые неактивны более 60 сек
        self._cleanup_connections(now)

    def _cleanup_connections(self, now):
        to_delete = []
        with self.lock:
            for conn_id, info in self.connections.items():
                if now - info["last"] > 60:
                    to_delete.append(conn_id)
            for conn_id in to_delete:
                del self.connections[conn_id]

            # Ограничиваем размер хранилища
            if len(self.connections) > self.max_connections:
                sorted_conns = sorted(self.connections.items(), key=lambda kv: kv[1]["last"])
                for conn_id, _ in sorted_conns[:len(self.connections) - self.max_connections]:
                    del self.connections[conn_id]

    def _add_event(self, event):
        """Добавить новое событие в очередь"""
        self.events.append(event)

    def get_events(self):
        """Получить все текущие события и очистить очередь"""
        with self.lock:
            evs = list(self.events)
            self.events.clear()
        return evs

# --- Пример запуска --- #
if __name__ == "__main__":
    print("Запуск RudyAnalyzer...")
    analyzer = RudyAnalyzer()
    analyzer.start()
    try:
        while True:
            time.sleep(5)
            evs = analyzer.get_events()
            if evs:
                for e in evs:
                    print(f"[{time.strftime('%H:%M:%S', time.localtime(e['timestamp']))}] {e['ip']}: {e['desc']}")
    except KeyboardInterrupt:
        print("Остановка RudyAnalyzer...")
        analyzer.stop()
