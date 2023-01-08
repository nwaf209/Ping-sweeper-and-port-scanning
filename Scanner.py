# TODO Error Handling & Reporting
# TODO Platform Compatibility
# TODO GUI Polishing
# TODO Code clean up & comments
# TODO Start, Stop and Resume functionality
# TODO fully functional progress bar
# TODO Proper indication of started scanning operations
# TODO Proper input disabling when scanning operations start
# TODO Faster port scanning if possible
# TODO Time column for each host port scan time to complete
# TODO Update OS when port scan gets it
# TODO App name and icon changes
# TODO complete .exe


import subprocess
import sys
import csv
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


class Port:
    def __init__(self, port, name, product, version):
        self.port = port
        self.name = name
        self.product = product
        self.version = version


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
    ips = []

    def __init__(self):
        super(MainWindow, self).__init__()
        loadUi("App.ui", self)
        self.pushButton.clicked.connect(self.scan)
        self.pushButton_2.clicked.connect(self.port_scan)
        self.actionStatus.changed.connect(self.hide_status)
        self.actionIP.changed.connect(self.hide_ip)
        self.actionMac.changed.connect(self.hide_mac)
        self.actionHost_Name.changed.connect(self.hide_host_name)
        self.actionOS.changed.connect(self.hide_os)
        self.actionManufacturer.changed.connect(self.hide_manu)
        self.comboBox.currentIndexChanged.connect(self.selected_ports_disabler)
        self.actionDownload_as_csv_file.triggered.connect(self.download)
        self.actionAbout.triggered.connect(self.about)

    def about(self):
        msg = QtWidgets.QMessageBox()
        msg.setWindowTitle('About')
        msg.setGeometry(800, 500, 900, 900)
        msg.setText('This is a Ping Sweep program with some port scanning functionalities and a GUI')
        msg.setIcon(QtWidgets.QMessageBox.Information)
        x = msg.exec_()

    def download(self):
        header = ['', 'Status', 'IP', 'Mac', 'Host Name', 'OS', 'Manufacturer']
        f = open('ping_data.csv', 'w', newline='')
        writer = csv.writer(f)
        writer.writerow(header)
        for i in range(len(MainWindow.ips)):
            x = self.treeWidget.topLevelItem(i)
            row = []
            for p in range(7):
                row.append(x.text(p))
            writer.writerow(row)
            cc = x.childCount()
            if cc > 0:
                for q in range(cc):
                    ch = x.child(q)
                    row = []
                    for p in range(4):
                        row.append(ch.text(p))
                    writer.writerow(row)
        f.close()

    def selected_ports_disabler(self):
        if self.comboBox.currentIndex() == 1:
            self.spinBox_3.setEnabled(True)
            self.spinBox.setEnabled(False)
            self.spinBox_2.setEnabled(False)
        elif self.comboBox.currentIndex() == 2:
            self.spinBox_3.setEnabled(False)
            self.spinBox.setEnabled(True)
            self.spinBox_2.setEnabled(True)
        else:
            self.spinBox_3.setEnabled(False)
            self.spinBox.setEnabled(False)
            self.spinBox_2.setEnabled(False)

    def hide_status(self):
        if not self.actionStatus.isChecked():
            self.treeWidget.setColumnHidden(1, True)
        else:
            self.treeWidget.setColumnHidden(1, False)

    def hide_ip(self):
        if not self.actionIP.isChecked():
            self.treeWidget.setColumnHidden(2, True)
        else:
            self.treeWidget.setColumnHidden(2, False)

    def hide_mac(self):
        if not self.actionMac.isChecked():
            self.treeWidget.setColumnHidden(3, True)
        else:
            self.treeWidget.setColumnHidden(3, False)

    def hide_host_name(self):
        if not self.actionHost_Name.isChecked():
            self.treeWidget.setColumnHidden(4, True)
        else:
            self.treeWidget.setColumnHidden(4, False)

    def hide_os(self):
        if not self.actionOS.isChecked():
            self.treeWidget.setColumnHidden(5, True)
        else:
            self.treeWidget.setColumnHidden(5, False)

    def hide_manu(self):
        if not self.actionManufacturer.isChecked():
            self.treeWidget.setColumnHidden(6, True)
        else:
            self.treeWidget.setColumnHidden(6, False)

    def scan(self):
        MainWindow.p_val = []
        MainWindow.ips = []
        self.pushButton.setEnabled(False)
        self.pushButton_2.setEnabled(False)
        self.textEdit.clear()
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

    def port_scan(self):
        MainWindow.p_val = []
        selected_ips = []
        # self.pushButton.setEnabled(False)
        # self.pushButton_2.setEnabled(False)
        self.pBar.reset()
        self.pBar.setValue(0)
        self.pBar.setMaximum(len(MainWindow.ips))
        ai = self.comboBox_3.currentText()
        method = self.comboBox_2.currentIndex()
        if method == 0:
            command = '-sT'
        elif method == 1:
            command = '-sS'
        elif method == 2:
            command = '-sX'
        elif method == 3:
            command = '-sA'
        elif method == 4:
            command = '-sU'
        selected = self.comboBox.currentText()
        if ai == 'All Hosts':
            if selected == 'all':
                for ip in MainWindow.ips:
                    t = threading.Thread(target=MainWindow.port_scan_all, args=[self, ip, command])
                    t.start()
            elif selected == 'singal port':
                for ip in MainWindow.ips:
                    p = self.spinBox_3.value()
                    t = threading.Thread(target=MainWindow.port_scan_singal, args=[self, ip, str(p), command])
                    t.start()
            elif selected == 'range':
                for ip in MainWindow.ips:
                    fp = self.spinBox.value()
                    lp = self.spinBox_2.value()
                    if fp < lp:
                        range = str(fp) + '-' + str(lp)
                    elif lp > fp:
                        range = str(lp) + '-' + str(fp)
                    elif fp == lp:
                        range = str(lp)
                    t = threading.Thread(target=MainWindow.port_scan_range, args=[self, ip, range, command])
                    t.start()
            elif selected == 'common':
                for ip in MainWindow.ips:
                    t = threading.Thread(target=MainWindow.port_scan_common, args=[self, ip, command])
                    t.start()
        elif ai == 'Individual Hosts':
            for ip in MainWindow.ips:
                t = self.treeWidget.findItems(str(ip), Qt.MatchFlag.MatchExactly, 2)[0]
                if t.checkState(0) == 2:
                    selected_ips.append(ip)
            if selected == 'all':
                for ip in selected_ips:
                    t = threading.Thread(target=MainWindow.port_scan_all, args=[self, ip, command])
                    t.start()
            elif selected == 'singal port':
                for ip in selected_ips:
                    p = self.spinBox_3.value()
                    t = threading.Thread(target=MainWindow.port_scan_singal, args=[self, ip, str(p), command])
                    t.start()
            elif selected == 'range':
                for ip in selected_ips:
                    fp = self.spinBox.value()
                    lp = self.spinBox_2.value()
                    if fp < lp:
                        range = str(fp) + '-' + str(lp)
                    elif lp > fp:
                        range = str(lp) + '-' + str(fp)
                    elif fp == lp:
                        range = str(lp)
                    t = threading.Thread(target=MainWindow.port_scan_range, args=[self, ip, range, command])
                    t.start()
            elif selected == 'common':
                for ip in selected_ips:
                    t = threading.Thread(target=MainWindow.port_scan_common, args=[self, ip, command])
                    t.start()

    def port_scan_all(self, ip, method):
        out = False
        args = 'nmap ' + method + ' -sV -p 1-65535 -Pn'
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip, arguments=args, timeout=700)
        except nmap.PortScannerTimeout as exc:
            print(ip + '  Scan Complete is timed out')
        #    MainWindow.evt_update(self, 0)
            return 0
        if len(nm.all_hosts()) == 0:
            out = True
        if out:
            print(ip + '  Scan Complete is out')
        #    MainWindow.evt_update(self, 0)
        if not out:
            for proto in nm[ip].all_protocols():
                for port in nm[ip].all_tcp():
                    if nm[ip][proto][port]['state'] == 'open' or nm[ip][proto][port]['state'] == 'filtered':
                        pp = Port(port, nm[ip]['tcp'][int(port)]['name'], nm[ip]['tcp'][int(port)]['product'],
                                  nm[ip]['tcp'][int(port)]['version'])
                        MainWindow.add_child(self, ip, pp)
                        print('done  ' + ip + ' ' + str(port))
            #            MainWindow.evt_update(self, 0)
            print(ip + '  Scan Complete')

    def port_scan_range(self, ip, range, method):
        out = False
        args = 'nmap ' + method + ' -sV -p ' + str(range) + ' -Pn'
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip, arguments=args, timeout=700)
        except nmap.PortScannerTimeout as exc:
            print(ip + '  Scan Complete is timed out')
            return 0
        if len(nm.all_hosts()) == 0:
            out = True
        #    MainWindow.evt_update(self, 0)
        if out:
            print(ip + '  Scan Complete is out')
        if not out:
            for proto in nm[ip].all_protocols():
                for port in nm[ip].all_tcp():
                    if nm[ip][proto][port]['state'] == 'open' or nm[ip][proto][port]['state'] == 'filtered':
                        pp = Port(port, nm[ip]['tcp'][int(port)]['name'], nm[ip]['tcp'][int(port)]['product'],
                                  nm[ip]['tcp'][int(port)]['version'])
                        MainWindow.add_child(self, ip, pp)
                        print('done  ' + ip + ' ' + str(port))
            #           MainWindow.evt_update(self, 0)
            print(ip + '  Scan Complete')

    def port_scan_common(self, ip, method):
        out = False
        args = 'nmap ' + method + ' -sV --top-ports 1000 -Pn'
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip, arguments=args, timeout=600)
        except nmap.PortScannerTimeout as exc:
            print(ip + '  Scan Complete is timed out')
            return 0
        if len(nm.all_hosts()) == 0:
            out = True
        #    MainWindow.evt_update(self, 0)
        if out:
            print(ip + '  Scan Complete is out')
        if not out:
            for proto in nm[ip].all_protocols():
                for port in nm[ip].all_tcp():
                    if nm[ip][proto][port]['state'] == 'open' or nm[ip][proto][port]['state'] == 'filtered':
                        pp = Port(port, nm[ip]['tcp'][int(port)]['name'], nm[ip]['tcp'][int(port)]['product'],
                                  nm[ip]['tcp'][int(port)]['version'])
                        MainWindow.add_child(self, ip, pp)
                        print('done  ' + ip + ' ' + str(port))
            #           MainWindow.evt_update(self, 0)
            print(ip + '  Scan Complete')

    def port_scan_singal(self, ip, p, method):
        out = False
        args = 'nmap ' + method + ' -sV -p ' + str(p) + ' -Pn'
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip, arguments=args, timeout=150)
        except nmap.PortScannerTimeout as exc:
            print(ip + '  Scan Complete is timed out')
        #    MainWindow.evt_update(self, 0)
            return 0
        if len(nm.all_hosts()) == 0:
            out = True
        if out:
            print(ip + '  Scan Complete is out')
        #    MainWindow.evt_update(self, 0)
        if not out:
            for proto in nm[ip].all_protocols():
                for port in nm[ip].all_tcp():
                    if nm[ip][proto][port]['state'] == 'open':
                        pp = Port(port, nm[ip]['tcp'][int(port)]['name'], nm[ip]['tcp'][int(port)]['product'],
                                  nm[ip]['tcp'][int(port)]['version'])
                        MainWindow.add_child(self, ip, pp)
                        print('done  ' + ip + ' ' + str(port))
        print(ip + '  Scan Complete')
        # MainWindow.evt_update(self, 0)

    def evt_update(self, val):
        MainWindow.p_val.append(val)
        self.pBar.setValue(len(MainWindow.p_val))
        if self.pBar.value() == self.pBar.maximum():
            self.pBar.reset()
            self.pBar.setValue(0)
            self.pushButton.setEnabled(True)
            self.pushButton_2.setEnabled(True)

    def add_row(self, entry):
        item = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item.setCheckState(0, Qt.CheckState.Unchecked)
        item.setText(1, entry.status)
        item.setText(2, entry.ip)
        item.setText(3, entry.mac)
        item.setText(4, entry.hostname)
        item.setText(5, entry.os)
        item.setText(6, entry.manufacturer)
        MainWindow.ips.append(entry.ip)
        # child = QtWidgets.QTreeWidgetItem(item)
        # child.setText(0, 'Port')
        # child.setText(1, 'Name')
        # child.setText(2, 'Product')
        # child.setText(3, 'Version')

    def add_child(self, ip, entry):
        t = self.treeWidget.findItems(str(ip), Qt.MatchFlag.MatchExactly, 2)[0]
        item = QtWidgets.QTreeWidgetItem(t)
        item.setText(1, str(entry.port))
        item.setText(2, entry.name)
        item.setText(3, entry.product)
        item.setText(4, entry.version)

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
        self.textEdit.insertPlainText(subnet + '0/24  ')
        for x in range(255):
            self.mt = MainThread(self, subnet, x)
            self.mt.update.connect(self.evt_update)
            self.mt.start()
            self.mt.wait(1)


t = threading.Thread(target=run)
t.start()
