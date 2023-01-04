# TODO Error Handling & Reporting
# TODO Platform Compatibility
# TODO GUI Polishing
# TODO Code clean up & comments
# TODO Start, Stop and Resume functionality
# TODO fully functional progress bar
# TODO Time column for each host port scan time to complete
# TODO Faster port scanning if possible
# TODO Return child dropdown arrow
# TODO Update OS when port scan gets it
# TODO Download as csv implemented
# TODO About implemented
# TODO App name and icon changes
# TODO complete .exe


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
    tcp = '1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,' \
          '143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,' \
          '427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,' \
          '646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,' \
          '898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,' \
          '1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,' \
          '1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,' \
          '1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,' \
          '1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,' \
          '1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,' \
          '2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,' \
          '2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,' \
          '2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,' \
          '2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,' \
          '3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,' \
          '3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,' \
          '3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,' \
          '4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,' \
          '5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,' \
          '5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,' \
          '5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,' \
          '5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,' \
          '6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,' \
          '7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,' \
          '7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,' \
          '8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,' \
          '8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,' \
          '9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,' \
          '9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,' \
          '10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,' \
          '14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,' \
          '17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,' \
          '21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,' \
          '30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,' \
          '44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,' \
          '50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,' \
          '56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389 '

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
            return 0
        if len(nm.all_hosts()) == 0:
            out = True
        #    MainWindow.evt_update(self, 0)
        if out:
            print(ip + '  Scan Complete is out')
        if not out:
            for proto in nm[ip].all_protocols():
                for port in nm[ip].all_tcp():
                    if nm[ip][proto][port]['state'] == 'open':
                        pp = Port(port, nm[ip]['tcp'][int(port)]['name'], nm[ip]['tcp'][int(port)]['product'],
                                  nm[ip]['tcp'][int(port)]['version'])
                        MainWindow.add_child(self, ip, pp)
                        print('done  ' + ip + ' ' + str(port))
            #           MainWindow.evt_update(self, 0)
        print(ip + '  Scan Complete')

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
            self.mt.wait(4)


t = threading.Thread(target=run)
t.start()
