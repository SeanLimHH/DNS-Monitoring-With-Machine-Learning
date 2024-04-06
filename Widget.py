import sys
from PyQt5.QtWidgets import QApplication, QPushButton, QWidget, QVBoxLayout, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QTextCursor
import subprocess
import sys
import os

currentDirectory = os.path.dirname(os.path.realpath(__file__))
activateVirtualEnvironment = os.path.join(currentDirectory, "Scripts", "activate")

print("currentDirectory", currentDirectory)
print("activateVirtualEnvironment", activateVirtualEnvironment)


class BackgroundProcess(QThread):

    updateSignal = pyqtSignal(str)

    def __init__(self, command, parent=None):
        super().__init__(parent)
        self.command = command

    def run(self):
        try:
            process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.updateSignal.emit(output.strip())
                    
            process.stdout.close()
            process.wait()
        except Exception as e:
            self.updateSignal.emit(f"Error: {e}")


class DNSMonitoringWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.thread = None

    def initUI(self):
        self.setWindowTitle('DNS Monitoring')
        self.setFixedSize(1000, 800)


        DNSScanButton = QPushButton('Scan DNS Cache', self)
        DNSScanButton.clicked.connect(self.scanDNSCache)
        DNSScanButton.setFixedSize(250, 50)

        realTimeScanButton = QPushButton('Begin Real-Time Monitoring', self)
        realTimeScanButton.clicked.connect(self.beginRealTimeScan)
        realTimeScanButton.setFixedSize(250, 50)

        stopButton = QPushButton('Stop', self)
        stopButton.clicked.connect(self.stopScan)
        stopButton.setFixedSize(250, 50)



        self.outputText = QTextEdit(self)
        self.outputText.setReadOnly(True)


    
        layout = QVBoxLayout() # We stack the buttons vertically.
        layout.addSpacing(20)
        layout.addWidget(DNSScanButton)
        layout.addWidget(realTimeScanButton)
        layout.addWidget(stopButton)
        layout.addWidget(self.outputText)

        
        self.activateEnvironment()


        layout.setAlignment(DNSScanButton, Qt.AlignCenter)
        layout.setAlignment(realTimeScanButton, Qt.AlignCenter)
        layout.setAlignment(stopButton, Qt.AlignCenter)
        self.setLayout(layout)
        self.center()
        self.show()

    def center(self):
        screenGeometry = QApplication.desktop().screenGeometry()
        self.move(screenGeometry.width()//2 - self.width()//2, screenGeometry.height()//2 - self.height()//2)
    
    def activateEnvironment(self):
        try:
            subprocess.run([activateVirtualEnvironment], shell=True, check=True)
            subprocess.run(["cd", currentDirectory], shell=True, check=True)
        except subprocess.CalledProcessError as e:
            self.updateLog(f"Error activating virtual environment: {e}")
            return False
        return True

    def scanDNSCache(self):
        self.outputText.clear()
        self.updateLog("DNS Cache Scan starting...\n")
        self.thread = BackgroundProcess(["python", "DNSCacheScans.py"])
        self.thread.updateSignal.connect(self.updateLog)
        self.thread.start()


    def beginRealTimeScan(self):

        self.outputText.clear()
        self.updateLog("Real-Time Monitoring starting...\n")
        self.thread = BackgroundProcess(["python", "DNSRealTimeScans.py"])
        self.thread.updateSignal.connect(self.updateLog)
        self.thread.start()


    def updateLog(self, text):
        self.outputText.append(text)

    def stopScan(self):
        if self.thread and self.thread.isRunning():
            self.thread.terminate()
            self.updateLog("\nScan stopped.\n")
        else:
            self.updateLog("\nNo scan is currently running.\n")
def run():
    app = QApplication(sys.argv)
    window = DNSMonitoringWidget()
    sys.exit(app.exec_())
