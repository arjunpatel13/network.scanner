from PyQt5 import QtCore, QtGui, QtWidgets
import subprocess
from scapy.all import ARP, Ether, srp
import socket
class Ui_MainWindow(object):
    def getNetworkInformation(self):
        proc = subprocess.check_output("ipconfig" ).decode('utf-8')
        l = proc.split("\r\n")
        l.remove('')
        info = l[-13] +"\n"+ l[-11] +"\n"+ l[-10]+"\n"+l[-9]+"\n"+l[-8]+"\n"+l[-7]
        self.targetIp = l[-7].split(":")[1].strip(" ")
        print(self.targetIp)
        self.lblNetworkInfor.setText(info)

    def startScanning(self):
        self.listNetworks.clear()
        self.progressBar.setValue(0)
        target_ip = self.targetIp+"/24"
        self.btnStart.setDisabled(True)
        try:
            # IP Address for the destination
            # create ARP packet
            arp = ARP(pdst=target_ip)
            # create the Ether broadcast packet
            # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            # stack them
            packet = ether/arp

            result = srp(packet, timeout=3, verbose=0)[0]
            progress = 100 / len(result)
            # a list of clients, we will fill this in the upcoming loop
            clients = []
            for sent, received in result:
                self.progressBar.setValue(progress)
                host = "Host"
                try:
                    host = socket.gethostbyaddr(received.psrc)[0]
                    #pass
                except Exception as e:
                    print(e)
                progress += progress
                # for each response, append ip and mac address to `clients` list
                clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'host': host})
            self.progressBar.setValue(100)
            # print clients
            print("Available devices in the network:")
            self.listNetworks.addItem("%-20s %-20s %-30s" % ("IP", "MAC", "HOSTNAME"))#print("IP" + " "*18+"%-12i").format("HOST")
            for client in clients:
                self.listNetworks.addItem("%-20s %-20s %-20s" % (client['ip'], client['mac'], client['host']))
                #print("{:16}    {}     {}".format(client['ip'], client['mac'], client['host']))
            self.btnStart.setDisabled(False)
        except Exception as e:
            print(e)
    def Exit(self):
        exit(1)
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1185, 706)
        self.lblNetworkInfor = QtWidgets.QLabel(MainWindow)
        self.lblNetworkInfor.setGeometry(QtCore.QRect(60, 110, 511, 341))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.lblNetworkInfor.setFont(font)
        self.lblNetworkInfor.setStyleSheet("QLabel{border-style:solid;border-width:1px;border-color:grey;border-radius:20px;}")
        self.lblNetworkInfor.setObjectName("lblNetworkInfor")
        self.listNetworks = QtWidgets.QListWidget(MainWindow)
        self.listNetworks.setGeometry(QtCore.QRect(670, 40, 471, 621))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.listNetworks.setFont(font)
        self.listNetworks.setWhatsThis("")
        self.listNetworks.setStyleSheet("QListWidget{border-style:solid;border-width:1px;border-color:grey;border-radius:10px;}")
        self.listNetworks.setObjectName("listNetworks")
        self.progressBar = QtWidgets.QProgressBar(MainWindow)
        self.progressBar.setGeometry(QtCore.QRect(70, 520, 511, 31))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName("progressBar")
        self.btnStart = QtWidgets.QPushButton(MainWindow)
        self.btnStart.setGeometry(QtCore.QRect(70, 580, 181, 61))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.btnStart.setFont(font)
        self.btnStart.setStyleSheet("QPushButton{border-style:solid;border-width:1px;border-color:grey;border-radius:10px;}QPushButton:hover{background-color:grey;color:white;border-style:solid;border-width:1px;border-color:grey;border-radius:10px;}")
        self.btnStart.setObjectName("btnStart")
        self.btnExit = QtWidgets.QPushButton(MainWindow)
        self.btnExit.setGeometry(QtCore.QRect(390, 580, 181, 61))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.btnExit.setFont(font)
        self.btnExit.setStyleSheet("QPushButton{border-style:solid;border-width:1px;border-color:grey;border-radius:10px;}QPushButton:hover{background-color:grey;color:white;border-style:solid;border-width:1px;border-color:grey;border-radius:10px;}")
        self.btnExit.setObjectName("btnExit")
        self.label_2 = QtWidgets.QLabel(MainWindow)
        self.label_2.setGeometry(QtCore.QRect(60, 50, 451, 41))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))      
        self.btnStart.setText(_translate("MainWindow", "Start"))
        self.btnExit.setText(_translate("MainWindow", "Exit"))
        self.label_2.setText(_translate("MainWindow", "Network Information"))
        self.getNetworkInformation()
        self.btnStart.clicked.connect(self.startScanning)
        self.btnExit.clicked.connect(self.Exit)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QWidget()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
