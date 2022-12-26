# TODO Error Handling & Reporting
# TODO Platform Compatibility
# TODO GUI Polishing
# TODO Code clean up & comments

import subprocess
import sys
import os
import platform
from subprocess import check_output
import requests
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow
import threading
import queue
import time
import nmap3
import nmap


class IP:
    def __init__(self, ip, hostname, mac, manufacturer, osys, status):
        self.ip = ip
        self.hostname = hostname
        self.mac = mac
        self.manufacturer = manufacturer
        self.os = osys
        self.status = status


def run():
    app = QApplication(sys.argv)
    w = MainWindow()
    widget = QtWidgets.QStackedWidget()
    widget.addWidget(w)
    # widget.setFixedHeight(900)
    widget.setGeometry(300, 100, 1400, 900)
    # widget.setFixedWidth(1200)
    widget.show()
    try:
        sys.exit(app.exec_())
    except:
        print("Exiting")


parent_threads = []
threads = []


class MainThread(QThread):
    def __init__(self, w, subnet, p):
        super(QThread, self).__init__()
        self.__w = w
        self.__subnet = subnet
        self.__p = p
    update = pyqtSignal(int)

    def run(self):
        val = MainWindow.ping(self.__w, self.__p, self.__subnet)
        self.update.emit(val)


class MainWindow(QMainWindow):
    p_val = []

    def __init__(self):
        super(MainWindow, self).__init__()
        loadUi("App.ui", self)
        self.pushButton.clicked.connect(self.scan)
        self.pushButton_2.clicked.connect(self.port_scan_all)

    def scan(self):
        MainWindow.p_val = []
        self.pBar.reset()
        self.pBar.setValue(0)
        self.treeWidget.clear()
        config = check_output('ipconfig /all', universal_newlines=True)
        networks = config.split('IPv4 Address. . . . . . . . . . . :')
        maxp = (len(networks) - 1) * 255
        self.pBar.setMaximum(maxp)
        for i in range(len(networks) - 1):
            t = threading.Thread(target=MainWindow.multi_network, args=[self, networks, i])
            t.start()
            parent_threads.append(t)

    def port_scan_all(self):
        nm = nmap.PortScanner()
        nm.scan('192.168.100.0/24', '1-65535')
        for host in nm.all_hosts():
            print(nm[host].all_tcp())

    def evt_update(self, val):
        MainWindow.p_val.append(val)
        self.pBar.setValue(len(MainWindow.p_val))

    def add_row(self, entry):
        item = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item.setText(0, entry.status)
        item.setText(1, entry.ip)
        item.setText(2, entry.mac)
        item.setText(3, entry.hostname)
        item.setText(4, entry.os)
        item.setText(5, entry.manufacturer)

    def ping(self, p, subnet):
        status = 'alive'
        try:
            o = check_output('ping -a ' + str(subnet) + str(p) + ' -n 1 ', universal_newlines=True)
        except subprocess.CalledProcessError as exc:
            o = exc.output
            a = check_output('arp -a', universal_newlines=True)
            if a.find(str(subnet) + str(p) + ' ') > -1:
                status = status + '/filtered'
            else:
                return 0
        if o.find('unreachable') > -1:
            return 0
        try:
            r = o.split('Pinging ')
            t = r[1].rsplit(' with')
            ih = t[0]
            h = ih.split(' [')
            if len(h) == 2:
                host = h[0]
                q = h[1].rsplit(']')
                ip = q[0]
            else:
                host = 'Unknown'
                ip = h[0]

            if status == 'alive':
                r = t[1].split('TTL=')
                t = r[1].rsplit('Ping ')
                ttl = t[0]
                if int(ttl) == 32:
                    os = 'Windows 95/98/ME'
                elif int(ttl) == 64:
                    os = 'Linux/Unix'
                elif int(ttl) == 128:
                    os = 'Windows XP/7/8/2003/2008'
                elif int(ttl) == 255:
                    os = 'Solaris'
            else:
                os = 'Unknown'
            j = check_output('ipconfig /all', universal_newlines=True)
            tmp1 = j.split('IPv4 Address. . . . . . . . . . . :')
            for i in range(len(tmp1) - 1):
                tmp2 = tmp1[i + 1].splitlines()
                tmp3 = tmp2[0].replace(" ", "").split('.')
                tmp4 = tmp3[3].split('(')
                tmp3[3] = tmp4[0]
                tmp5 = '.'.join(tmp3)
                if ip == tmp5:
                    mainIp = tmp5
                    break
                else:
                    mainIp = ''
            a = check_output('arp -a', universal_newlines=True)
            if ip == mainIp:
                j = check_output('ipconfig /all', universal_newlines=True)
                tmp1 = j.split(str(ip))
                tmp2 = tmp1[0].rsplit('Physical Address. . . . . . . . . :', 1)
                tmp3 = tmp2[1].splitlines()
                mac = ''.join(tmp3[0].split())
                response = requests.request("GET", 'https://api.maclookup.app/v2/macs/' + mac)
                if response.status_code == 200:
                    tmp1 = response.text.split('company')
                    tmp2 = tmp1[1].split(',', 1)
                    tmp3 = tmp2[0].split('":"')
                    tmp4 = tmp3[1].split('"')
                    company = tmp4[0]
                else:
                    company = 'Unknown'
                entry = IP(str(ip), host, mac, company, os, status)
                MainWindow.add_row(self, entry)
                return 0
            v = a.split(ip + ' ')
            m = v[1].split('dynamic')
            ma = m[0]
            mac = ma.replace(" ", "")
            response = requests.request("GET", 'https://api.maclookup.app/v2/macs/' + mac)
            if response.status_code == 200:
                tmp1 = response.text.split('company')
                tmp2 = tmp1[1].split(',', 1)
                tmp3 = tmp2[0].split('":"')
                tmp4 = tmp3[1].split('"')
                company = tmp4[0]
                if company == '':
                    company = 'Unknown'
            else:
                company = 'Unknown'
            entry = IP(str(ip), host, mac, company, os, status)
            MainWindow.add_row(self, entry)
            return 0
        except IndexError:
            print('An out of bounds index error has accord')

    def multi_network(self, networks, i):
        ipv4 = networks[i + 1].splitlines()
        mask = ipv4[0].replace(" ", "").split('.')
        mask[3] = ''
        subnet = '.'.join(mask)
        for x in range(255):
            self.mt = MainThread(self, subnet, x)
            self.mt.update.connect(self.evt_update)
            self.mt.start()
            self.mt.wait(3)


t = threading.Thread(target=run)
t.start()
