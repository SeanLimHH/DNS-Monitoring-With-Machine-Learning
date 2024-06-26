import sys
from PyQt5.QtWidgets import QApplication, QPushButton, QLabel, QWidget, QHBoxLayout, QVBoxLayout, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QTextCursor
import subprocess
import sys
import os

currentDirectory = os.path.dirname(os.path.realpath(__file__))
activateVirtualEnvironment = os.path.join(currentDirectory, "Scripts", "activate")


class BackgroundProcess(QThread):

    updateSignal = pyqtSignal(str)

    def __init__(self, command, parent=None):
        super().__init__(parent)
        self.command = command

    def run(self):
        try:
            process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, creationflags=subprocess.CREATE_NO_WINDOW)
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
        self.realTimeMonitoringRunning = False
        self.scanCacheRunning = False

    def initUI(self):
        self.setWindowTitle('DNS Monitoring')
        self.setFixedSize(1000, 800)

        self.DNSScanButton = QPushButton('Scan DNS Cache', self)
        self.DNSScanButton.clicked.connect(self.startScanCache)
        self.DNSScanButton.setFixedSize(250, 50)

        self.realTimeToggleButton = QPushButton('Start Real-Time Monitoring', self)
        self.realTimeToggleButton.clicked.connect(self.toggleRealTimeMonitoring)
        self.realTimeToggleButton.setFixedSize(250, 50)

        self.indicatorLabel = QLabel(self)
        self.indicatorLabel.setFixedSize(20, 20)
        self.updateIndicator()

        self.saveOutputButton = QPushButton('Save Output', self)
        self.saveOutputButton.clicked.connect(self.saveOutputToFile)
        self.saveOutputButton.setFixedSize(250, 50)

        self.outputText = QTextEdit(self)
        self.outputText.setReadOnly(True)

        indicatorLayout = QHBoxLayout() # Put the indicator beside

        buttonsLayout = QVBoxLayout() # Because we stack the two buttons
        buttonsLayout.addWidget(self.DNSScanButton)
        buttonsLayout.addWidget(self.realTimeToggleButton)
        buttonsLayout.addWidget(self.saveOutputButton)
        buttonsLayout.setAlignment(Qt.AlignCenter)
        

        indicatorLayout.addLayout(buttonsLayout)
        indicatorLayout.addWidget(QLabel("Monitoring Status:"), alignment=Qt.AlignRight)
        indicatorLayout.addWidget(self.indicatorLabel, alignment=Qt.AlignLeft)


        
        layout = QVBoxLayout() 
        layout.addSpacing(20)
        layout.addLayout(indicatorLayout)
        layout.addWidget(self.outputText)

        self.activateEnvironment()

        layout.setAlignment(self.DNSScanButton, Qt.AlignCenter)
        layout.setAlignment(self.realTimeToggleButton, Qt.AlignCenter)
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

    def startScanCache(self):
        self.outputText.clear()
        self.updateLog("DNS Cache Scan starting...\n")
        self.thread = BackgroundProcess(["python", "DNSCacheScans.py"])
        self.thread.updateSignal.connect(self.updateLog)
        self.thread.start()


    def toggleRealTimeMonitoring(self):
        
        if not self.realTimeMonitoringRunning:
            self.startRealTimeMonitoring()
        else:
            self.stopRealTimeMonitoring()
        self.updateRealTimeToggleButton()
        self.updateIndicator()

    def startRealTimeMonitoring(self):
        self.outputText.clear()
        self.updateLog("Real-Time Monitoring starting...\n")
        self.thread = BackgroundProcess(["python", "DNSRealTimeScans.py"])
        self.thread.updateSignal.connect(self.updateLog)
        self.thread.started.connect(self.updateIndicator)
        self.thread.finished.connect(self.updateIndicator)
        self.thread.started.connect(self.updateRealTimeToggleButton) 
        self.thread.finished.connect(self.updateRealTimeToggleButton)
        self.thread.start()
        self.realTimeMonitoringRunning = True

    def stopRealTimeMonitoring(self):
        if self.thread and self.thread.isRunning():
            self.thread.terminate()  # Terminate the background process
            self.thread.wait()  # Wait for the thread to finish gracefully
        self.realTimeMonitoringRunning = False
        self.updateLog("\nReal-Time Monitoring stopped.\n")

    def updateIndicator(self):
        # We need the hasattr simply to do a check if the properties have been initialised first
        if hasattr(self, 'realTimeMonitoringRunning') and hasattr(self, 'scanCacheRunning'):
            if self.realTimeMonitoringRunning or self.scanCacheRunning:
                self.indicatorLabel.setStyleSheet("background-color: green; border-radius: 10px;")
            else:
                self.indicatorLabel.setStyleSheet("background-color: red; border-radius: 10px;")
        else:
            self.indicatorLabel.setStyleSheet("background-color: red; border-radius: 10px;")

    def updateRealTimeToggleButton(self):
        # boolean single button logic - if on then make it off next.
        if self.realTimeMonitoringRunning:
            self.realTimeToggleButton.setText('Stop Real-Time Monitoring')
        else:
            self.realTimeToggleButton.setText('Start Real-Time Monitoring')


    def updateLog(self, text):
        self.outputText.append(text)

    def saveOutputToFile(self):
        if currentDirectory:
            print(currentDirectory)
            filePath = os.path.join(currentDirectory, 'output.txt')
            with open(filePath, 'w') as file:
                file.write(self.outputText.toPlainText())
            self.updateLog("\nOutput saved to output.txt.\n")


def run():
    app = QApplication(sys.argv)
    window = DNSMonitoringWidget()
    sys.exit(app.exec_())

run()
