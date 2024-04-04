import sys
from PyQt5.QtWidgets import QApplication, QPushButton, QWidget, QVBoxLayout, QDesktopWidget
from PyQt5 import QtCore

class DNSMonitoringWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('DNS Monitoring')
        button = QPushButton('Test', self)
        button.clicked.connect(self.testClick)
    
        layout = QVBoxLayout() # We stack the buttons vertically.
        layout.addWidget(button)
        self.setLayout(layout)
        layout.setAlignment(button, QtCore.Qt.AlignCenter)

        self.show()

    def testClick(self):
        print("Button clicked. Will run function here")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DNSMonitoringWidget()
    sys.exit(app.exec_())
