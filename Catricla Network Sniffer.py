import sys
import colorama
import ipaddress
import os
from scapy.all import sniff, IP, TCP, UDP
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget
from PyQt5.QtGui import QColor, QBrush
from PyQt5.QtCore import Qt, QThread, pyqtSignal

class PacketSniffer(QThread):
    packet_received = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self._running = False

    def run(self):
        self._running = True
        # Use a loop with a timeout to keep the thread responsive
        from scapy.all import conf
        while self._running:
            sniff(prn=self._emit_if_running, store=0, timeout=1)

    def _emit_if_running(self, pkt):
        if self._running:
            self.packet_received.emit(pkt)

    def stop(self):
        self._running = False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Catricla Network Monitor")
        self.resize(900, 500)
        self.setStyleSheet("""
            QMainWindow { background-color: #232629; }
            QTableWidget { background-color: #232629; color: #e0e0e0; gridline-color: #444; }
            QHeaderView::section { background-color: #31363b; color: #00bfff; font-weight: bold; }
            QTableWidget::item:selected { background-color: #3daee9; color: #232629; }
        """)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Protocol", "Source IP", "Destination IP", "Info"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget { alternate-background-color: #31363b; }
        """)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setDefaultSectionSize(180)
        layout = QVBoxLayout()
        layout.addWidget(self.table)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        self.sniffer = PacketSniffer()
        self.sniffer.packet_received.connect(self.add_packet)

        # Add Start/Stop buttons
        from PyQt5.QtWidgets import QPushButton, QHBoxLayout
        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop")
        self.start_btn.clicked.connect(self.start_sniffing)
        self.stop_btn.clicked.connect(self.stop_sniffing)
        self.stop_btn.setEnabled(False)
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)

    def start_sniffing(self):
        if not self.sniffer.isRunning():
            self.sniffer = PacketSniffer()
            self.sniffer.packet_received.connect(self.add_packet)
            self.sniffer.start()
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)

    def stop_sniffing(self):
        if self.sniffer.isRunning():
            self.sniffer.stop()
            self.sniffer.wait()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def add_packet(self, packet):
        if IP in packet:
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            info = packet.summary()

            # Discord detection only (no blocking DNS)
            discord_ips = [
                "162.159.128.0/19", "162.159.200.0/21", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/15", "141.101.72.0/24"
            ]
            import ipaddress
            is_discord = False
            for net in discord_ips:
                if ipaddress.ip_address(ip_dst) in ipaddress.ip_network(net):
                    is_discord = True
                    if ipaddress.ip_address(ip_src) in ipaddress.ip_network(net):
                        info = "Discord IP detected (both source and destination)"
                    is_Discord = False
                    info = "Discord IP detected"
                    try:
                        from scapy.layers.inet import IP
                        from scapy.layers.inet import TCP, UDP
                    except ImportError:
                        print("Scapy is not installed. Please install it using 'pip install scapy'.")
                        return
                    except ImportError:
                        print("colorama is not installed. Please install it using 'pip install colorama'.")
                        return
                    break

            row = self.table.rowCount()
            self.table.insertRow(row)
            proto_item = QTableWidgetItem(proto)
            if proto == "TCP":
                proto_item.setForeground(QBrush(QColor(0, 191, 255)))  # DeepSkyBlue
            elif proto == "UDP":
                proto_item.setForeground(QBrush(QColor(255, 0, 255)))  # Magenta
            else:
                proto_item.setForeground(QBrush(QColor(255, 255, 0)))  # Yellow
            self.table.setItem(row, 0, proto_item)
            self.table.setItem(row, 1, QTableWidgetItem(ip_src))
            dst_item = QTableWidgetItem(ip_dst)
            if is_discord:
                dst_item.setForeground(QBrush(QColor(114, 137, 218)))  # Discord blurple
                dst_item.setToolTip("Discord IP")
            self.table.setItem(row, 2, dst_item)
            info_item = QTableWidgetItem(info)
            info_item.setForeground(QBrush(QColor(200, 200, 200)))
            self.table.setItem(row, 3, info_item)
            self.table.scrollToBottom()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
