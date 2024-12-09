import os
import sqlite3
import sys
from datetime import date

import cv2
import numpy
from PyQt5.QtCore import QCoreApplication, QDate, QMetaObject, QRect, Qt
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtWidgets import (QApplication, QDateEdit, QLabel, QLineEdit,
                             QMainWindow, QMessageBox, QPushButton,
                             QTableWidget, QTableWidgetItem, QTabWidget,
                             QWidget)


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(633, 439)
        MainWindow.setStyleSheet("background-color: rgb(10, 50, 76);")
        
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        
        self.tabWidget = QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QRect(10, 20, 611, 401))
        self.tabWidget.setObjectName("tabWidget")
        
        # Login Tab
        self.tab = QWidget()
        self.tab.setObjectName("tab")
        
        self.label = QLabel(self.tab)
        self.label.setGeometry(QRect(0, 0, 611, 381))
        self.label.setPixmap(QPixmap("login.png"))
        self.label.setScaledContents(True)
        self.label.setObjectName("label")
        
        self.label_2 = QLabel(self.tab)
        self.label_2.setGeometry(QRect(20, 10, 281, 71))
        self.label_2.setStyleSheet("color: rgb(2, 255, 200); background-color: rgba(255, 255, 255, 0); font: 14pt 'Terminal';")
        self.label_2.setAlignment(Qt.AlignCenter)
        self.label_2.setWordWrap(True)
        self.label_2.setObjectName("label_2")
        
        self.LOGINBUTTON = QPushButton(self.tab)
        self.LOGINBUTTON.setGeometry(QRect(30, 260, 111, 61))
        self.LOGINBUTTON.setStyleSheet(
            "QPushButton#LOGINBUTTON {"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "padding:10px; font: 14pt 'Terminal';"
            "color: rgb(2, 255, 200); border-radius:20px; }"
            "QPushButton#LOGINBUTTON:hover {"
            "background-color: rgb(10,80,76); color: rgb(2, 255, 200); }"
        )
        self.LOGINBUTTON.setObjectName("LOGINBUTTON")
        
        self.CLOSE = QPushButton(self.tab)
        self.CLOSE.setGeometry(QRect(150, 260, 121, 61))
        self.CLOSE.setStyleSheet(
            "QPushButton#CLOSE {"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "padding:10px; font: 14pt 'Terminal';"
            "color: rgb(2, 255, 200); border-radius:20px; }"
            "QPushButton#CLOSE:hover {"
            "background-color: rgb(10,80,76); color: rgb(2, 255, 200); }"
        )
        self.CLOSE.setObjectName("CLOSE")
        
        self.LOGININFO = QLabel(self.tab)
        self.LOGININFO.setGeometry(QRect(40, 80, 241, 41))
        self.LOGININFO.setStyleSheet("font: 14pt 'Terminal'; color: rgb(2, 255, 200); background-color: rgba(255, 255, 255, 0);")
        self.LOGININFO.setObjectName("LOGININFO")
        
        self.PASSWORD = QLineEdit(self.tab)
        self.PASSWORD.setGeometry(QRect(30, 180, 241, 61))
        self.PASSWORD.setStyleSheet(
            "QLineEdit#PASSWORD { background-color: rgb(10, 50, 76);"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "color: rgb(2, 255, 200); padding:10px;"
            "font: 14pt 'Terminal'; border-radius:20px; }"
            "QLineEdit#PASSWORD:hover { background-color: rgb(10, 60, 76); }"
        )
        self.PASSWORD.setEchoMode(QLineEdit.Password)
        self.PASSWORD.setObjectName("PASSWORD")
        
        self.label_12 = QLabel(self.tab)
        self.label_12.setGeometry(QRect(40, 130, 241, 41))
        self.label_12.setStyleSheet("font: 14pt 'Terminal'; color: rgb(2, 255, 200); background-color: rgba(255, 255, 255, 0);")
        self.label_12.setObjectName("label_12")
        
        self.tabWidget.addTab(self.tab, "Login")

        # Mainform Tab
        self.tab_2 = QWidget()
        self.tab_2.setObjectName("tab_2")
        
        self.QLABEL2 = QLabel(self.tab_2)
        self.QLABEL2.setGeometry(QRect(0, 0, 611, 381))
        self.QLABEL2.setPixmap(QPixmap("mainform6.png"))
        self.QLABEL2.setScaledContents(True)
        self.QLABEL2.setObjectName("QLABEL2")
        
        self.TRAINLINK1 = QPushButton(self.tab_2)
        self.TRAINLINK1.setGeometry(QRect(50, 50, 191, 51))
        self.TRAINLINK1.setStyleSheet(
            "QPushButton#TRAINLINK1 {"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "padding:10px; font: 14pt 'Terminal';"
            "color: rgb(2, 255, 200); border-radius:20px; }"
            "QPushButton#TRAINLINK1:hover {"
            "background-color: rgb(10,80,76); color: rgb(2, 255, 200); }"
        )
        self.TRAINLINK1.setObjectName("TRAINLINK1")
        
        self.ATTLINK1 = QPushButton(self.tab_2)
        self.ATTLINK1.setGeometry(QRect(50, 120, 191, 51))
        self.ATTLINK1.setStyleSheet(
            "QPushButton#ATTLINK1 {"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "padding:10px; font: 14pt 'Terminal';"
            "color: rgb(2, 255, 200); border-radius:20px; }"
            "QPushButton#ATTLINK1:hover {"
            "background-color: rgb(10,80,76); color: rgb(2, 255, 200); }"
        )
        self.ATTLINK1.setObjectName("ATTLINK1")
        
        self.REPORTSLINK1 = QPushButton(self.tab_2)
        self.REPORTSLINK1.setGeometry(QRect(50, 200, 191, 51))
        self.REPORTSLINK1.setStyleSheet(
            "QPushButton#REPORTSLINK1 {"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "padding:10px; font: 14pt 'Terminal';"
            "color: rgb(2, 255, 200); border-radius:20px; }"
            "QPushButton#REPORTSLINK1:hover {"
            "background-color: rgb(10,80,76); color: rgb(2, 255, 200); }"
        )
        self.REPORTSLINK1.setObjectName("REPORTSLINK1")
        
        self.LOGOUTBUTTON = QPushButton(self.tab_2)
        self.LOGOUTBUTTON.setGeometry(QRect(50, 270, 191, 51))
        self.LOGOUTBUTTON.setStyleSheet(
            "QPushButton#LOGOUTBUTTON {"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "padding:10px; font: 14pt 'Terminal';"
            "color: rgb(2, 255, 200); border-radius:20px; }"
            "QPushButton#LOGOUTBUTTON:hover {"
            "background-color: rgb(10,80,76); color: rgb(2, 255, 200); }"
        )
        self.LOGOUTBUTTON.setObjectName("LOGOUTBUTTON")
        
        self.tabWidget.addTab(self.tab_2, "Mainform")

        # Training Tab
        self.tab_3 = QWidget()
        self.tab_3.setObjectName("tab_3")
        
        self.QLABEL2_2 = QLabel(self.tab_3)
        self.QLABEL2_2.setGeometry(QRect(0, 0, 611, 381))
        self.QLABEL2_2.setPixmap(QPixmap("mainform.png"))
        self.QLABEL2_2.setScaledContents(True)
        self.QLABEL2_2.setObjectName("QLABEL2_2")
        
        self.label_3 = QLabel(self.tab_3)
        self.label_3.setGeometry(QRect(60, 20, 181, 31))
        self.label_3.setStyleSheet("color: rgb(2, 255, 200); background-color: rgba(255, 255, 255, 0); font: 14pt 'Terminal';")
        self.label_3.setAlignment(Qt.AlignCenter)
        self.label_3.setWordWrap(True)
        self.label_3.setObjectName("label_3")
        
        self.traineeName = QLineEdit(self.tab_3)
        self.traineeName.setGeometry(QRect(30, 110, 241, 61))
        self.traineeName.setStyleSheet(
            "QLineEdit#traineeName { background-color: rgb(10, 50, 76);"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "color: rgb(2, 255, 200); padding:10px;"
            "font: 14pt 'Terminal'; border-radius:20px; }"
            "QLineEdit#traineeName:hover { background-color: rgb(10, 60, 76); }"
        )
        self.traineeName.setObjectName("traineeName")
        
        self.TRAININGBACK = QPushButton(self.tab_3)
        self.TRAININGBACK.setGeometry(QRect(160, 300, 111, 61))
        self.TRAININGBACK.setStyleSheet(
            "QPushButton#TRAININGBACK {"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "padding:10px; font: 14pt 'Terminal';"
            "color: rgb(2, 255, 200); border-radius:20px; }"
            "QPushButton#TRAININGBACK:hover {"
            "background-color: rgb(10,80,76); color: rgb(2, 255, 200); }"
        )
        self.TRAININGBACK.setObjectName("TRAININGBACK")
        self.TRAININGBACK.setText("GO BACK")
        
        self.tabWidget.addTab(self.tab_3, "Training")

        # Face Recognition Tab
        self.tab_4 = QWidget()
        self.tab_4.setObjectName("tab_4")
        
        self.QLABEL2_3 = QLabel(self.tab_4)
        self.QLABEL2_3.setGeometry(QRect(0, 0, 611, 381))
        self.QLABEL2_3.setPixmap(QPixmap("mainform2.png"))
        self.QLABEL2_3.setScaledContents(True)
        self.QLABEL2_3.setObjectName("QLABEL2_3")
        
        self.RECORD = QPushButton(self.tab_4)
        self.RECORD.setGeometry(QRect(40, 60, 221, 61))
        self.RECORD.setStyleSheet(
            "QPushButton#RECORD {"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "padding:10px; font: 14pt 'Terminal';"
            "color: rgb(2, 255, 200); border-radius:20px; }"
            "QPushButton#RECORD:hover {"
            "background-color: rgb(10,80,76); color: rgb(2, 255, 200); }"
        )
        self.RECORD.setObjectName("RECORD")
        
        self.tabWidget.addTab(self.tab_4, "Face Recognition")

        # Reports Tab
        self.tab_5 = QWidget()
        self.tab_5.setObjectName("tab_5")
        
        self.label_14 = QLabel(self.tab_5)
        self.label_14.setGeometry(QRect(0, 0, 601, 371))
        self.label_14.setPixmap(QPixmap("mainform5.png"))
        self.label_14.setScaledContents(True)
        self.label_14.setObjectName("label_14")
        
        self.REPORTSBACK = QPushButton(self.tab_5)
        self.REPORTSBACK.setGeometry(QRect(390, 300, 181, 51))
        self.REPORTSBACK.setStyleSheet(
            "QPushButton#REPORTSBACK {"
            "border-bottom:2px solid rgba(0,0,0,100);"
            "padding:10px; font: 14pt 'Terminal';"
            "color: rgb(2, 255, 200); border-radius:20px; }"
            "QPushButton#REPORTSBACK:hover {"
            "background-color: rgb(10,80,76); color: rgb(2, 255, 200); }"
        )
        self.REPORTSBACK.setObjectName("REPORTSBACK")
        
        self.tabWidget.addTab(self.tab_5, "Reports")
        
        MainWindow.setCentralWidget(self.centralwidget)
        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QMetaObject.connectSlotsByName(MainWindow)
        
    def retranslateUi(self, MainWindow):
        _translate = QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label_2.setText(_translate("MainWindow", "Face Recognition Attendance Login System"))
        self.LOGINBUTTON.setText(_translate("MainWindow", "Login"))
        self.CLOSE.setText(_translate("MainWindow", "Close"))
        self.label_12.setText(_translate("MainWindow", "Enter the password"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "Login"))
        self.TRAINLINK1.setText(_translate("MainWindow", "TRAIN USER"))
        self.REPORTSLINK1.setText(_translate("MainWindow", "REPORTS"))
        self.ATTLINK1.setText(_translate("MainWindow", "ATTENDANCE ENTRY"))
        self.LOGOUTBUTTON.setText(_translate("MainWindow", "LOGOUT"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "Mainform"))
        self.label_3.setText(_translate("MainWindow", "TRAINING PROCESS"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("MainWindow", "Training"))
        self.RECORD.setText(_translate("MainWindow", "RECORD ATTENDANCE"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_4), _translate("MainWindow", "Face Recognition"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_5), _translate("MainWindow", "Reports"))

class MainApp(QMainWindow, Ui_MainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.setupUi(self)
        self.tabWidget.setCurrentIndex(0)
        self.LOGINBUTTON.clicked.connect(self.login)
        self.LOGOUTBUTTON.clicked.connect(self.logout)
        self.CLOSE.clicked.connect(self.close_window)
        self.TRAINLINK1.clicked.connect(self.show_training_form)
        self.ATTLINK1.clicked.connect(self.show_attendance_entry_form)
        self.REPORTSLINK1.clicked.connect(self.show_reports_form)
        self.TRAININGBACK.clicked.connect(self.show_mainform)
        self.REPORTSBACK.clicked.connect(self.show_mainform)
        self.RECORD.clicked.connect(self.record_attendance)
        self.dateEdit = QDateEdit(self.tab_5)
        self.dateEdit.setGeometry(QRect(490, 80, 81, 22))
        self.dateEdit.setDate(date.today())
        self.dateEdit.dateChanged.connect(self.show_selected_date_reports)
        self.tabWidget.setStyleSheet("QTabWidget::pane{border:0;}")
        try:
            con = sqlite3.connect("face-reco.db")
            con.execute("CREATE TABLE IF NOT EXISTS attendance(attendanceid INTEGER, name TEXT, attendancedate TEXT)")
            con.commit()
            print("Table created successfully")
        except:
            print("Error in database")

    ### LOGIN PROCESS ###
    def login(self):
        pw = self.PASSWORD.text()
        if(pw == "123"):
            self.PASSWORD.setText("")
            self.LOGININFO.setText("")
            self.tabWidget.setCurrentIndex(1)
        else:
            self.LOGININFO.setText("Invalid Password..")
            self.PASSWORD.setText("")

    ### LOG OUT PROCESS ###
    def logout(self):
        self.tabWidget.setCurrentIndex(0)

    ### CLOSE WINDOW PROCESS ###
    def close_window(self):
        self.close()

    ### SHOW MAIN FORM ###
    def show_mainform(self):
        self.tabWidget.setCurrentIndex(1)

    ### SHOW TRAINING FORM ###
    def show_training_form(self):
        self.tabWidget.setCurrentIndex(2)

    ### SHOW ATTENDANCE ENTRY FORM ###
    def show_attendance_entry_form(self):
        self.tabWidget.setCurrentIndex(3)

    ### SHOW REPORTS FORM ###
    def show_reports_form(self):
        self.tabWidget.setCurrentIndex(4)

    ### RECORD ATTENDANCE ###
    def record_attendance(self):
        print("Recording attendance...")

    ### SHOW SELECTED DATE REPORTS ###
    def show_selected_date_reports(self):
        print("Selected date reports...")

def main():
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    app.exec_()

if __name__ == '__main__':
    main()
