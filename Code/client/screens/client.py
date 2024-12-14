# client.py

import sys
from PyQt5.QtWidgets import QApplication
from main_window import ClientApp

if __name__ == '__main__':
    app = QApplication(sys.argv)
    client = ClientApp()
    client.show()
    sys.exit(app.exec_())
