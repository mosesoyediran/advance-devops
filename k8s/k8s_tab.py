import os
import re
import shutil
import subprocess

import paramiko
from PyQt5.QtCore import QObject, QRunnable, Qt, QThreadPool, pyqtSignal
from PyQt5.QtWidgets import (QApplication, QLabel, QMessageBox, QPushButton,
                             QTabWidget, QVBoxLayout, QWidget)

from k8s.cluster_management_tab import ClusterManagementTab
from k8s.deployment_management_tab import DeploymentManagementTab
from k8s.node_management_tab import NodeManagementTab
from k8s.pod_management_tab import PodManagementTab
from k8s.service_management_tab import ServiceManagementTab


class WorkerSignals(QObject):
    """
    Defines the signals available from a running worker thread.
    """
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    progress = pyqtSignal(int)

class Worker(QRunnable):
    """
    Worker thread for executing functions in separate threads.
    """
    def __init__(self, fn, *args, **kwargs):
        super().__init__()

        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

        # Add the callback to our kwargs
        self.kwargs['progress_callback'] = self.signals.progress

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except subprocess.CalledProcessError as e:
            # Emit stderr as error
            self.signals.error.emit((e.returncode, e.stderr))
        except Exception as e:
            import sys
            import traceback
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()

class K8sTab(QWidget):
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.threadpool = QThreadPool()  # Initialize thread pool
        self.loaded_tabs = {}  # Cache for loaded tabs
        self.initUI()

    def initUI(self):
        main_layout = QVBoxLayout()  # Use QVBoxLayout to stack widgets vertically

        # Add the Back to System Button at the top
        back_button = QPushButton("Back to System")
        back_button.clicked.connect(self.go_back_to_system)
        back_button.setFixedSize(120, 30)
        main_layout.addWidget(back_button)

        # Create QTabWidget for subtabs
        self.sub_tab_widget = QTabWidget()

        # Define tab names and their corresponding classes
        self.tabs_info = {
            "Cluster Management": ClusterManagementTab,
            "Node Management": NodeManagementTab,
            "Deployment Management": DeploymentManagementTab,
            "Service Management": ServiceManagementTab,
            "Pod Management": PodManagementTab
        }

        # Add placeholder tabs
        for tab_name in self.tabs_info.keys():
            if tab_name == "Cluster Management":
                # Initialize ClusterManagementTab immediately
                subtab_instance = self.tabs_info[tab_name](self.auth_manager, self.main_tab_widget)
                self.loaded_tabs[tab_name] = subtab_instance
                self.sub_tab_widget.addTab(subtab_instance, tab_name)
            else:
                # Add placeholders for other tabs
                placeholder = QWidget()
                placeholder_layout = QVBoxLayout()
                placeholder_layout.setAlignment(Qt.AlignCenter)
                label = QLabel("Loading...")
                placeholder_layout.addWidget(label)
                placeholder.setLayout(placeholder_layout)
                self.sub_tab_widget.addTab(placeholder, tab_name)

        # Connect to the tab change event for lazy loading
        self.sub_tab_widget.currentChanged.connect(self.on_tab_changed)

        # Add the QTabWidget to the main_layout
        main_layout.addWidget(self.sub_tab_widget)
        self.setLayout(main_layout)

        # Optionally, load the first tab immediately (already done above)

    def go_back_to_system(self):
        """
        Switch back to the System tab.
        """
        from system_tab import \
            SystemTab  # Ensure system_tab is imported correctly

        # Remove all current tabs
        for i in reversed(range(self.main_tab_widget.count())):
            self.main_tab_widget.removeTab(i)

        # Add the System tab
        system_tab = SystemTab(self.auth_manager, self.main_tab_widget)
        self.main_tab_widget.addTab(system_tab, "System")
        self.main_tab_widget.setCurrentWidget(system_tab)

    def on_tab_changed(self, index):
        """
        Handle the event when a tab is changed.
        """
        # Get the tab name
        tab_name = self.sub_tab_widget.tabText(index)

        # Check if the tab is already loaded
        if tab_name in self.loaded_tabs:
            # Tab is already loaded; no action needed
            return

        # Replace the placeholder with the actual subtab
        placeholder = self.sub_tab_widget.widget(index)
        if isinstance(placeholder, QWidget) and placeholder.layout().itemAt(0).widget().text() == "Loading...":
            # Initialize the subtab
            subtab_class = self.tabs_info.get(tab_name)
            if subtab_class:
                subtab_instance = subtab_class(self.auth_manager, self.main_tab_widget)
                self.loaded_tabs[tab_name] = subtab_instance  # Cache the loaded tab

                # Replace the placeholder with the actual subtab
                self.sub_tab_widget.removeTab(index)
                self.sub_tab_widget.insertTab(index, subtab_instance, tab_name)

                # Optionally, set the current tab back to the one just loaded
                self.sub_tab_widget.setCurrentIndex(index)

    def load_tab_async(self, tab_name):
        """
        Optional: Preload specific tabs in the background.
        """
        if tab_name in self.loaded_tabs:
            return  # Already loaded

        worker = Worker(self.initialize_subtab, tab_name)
        worker.signals.result.connect(self.on_subtab_loaded)
        worker.signals.error.connect(self.on_error)
        self.threadpool.start(worker)

    def initialize_subtab(self, tab_name, progress_callback):
        """
        Function to initialize a subtab.
        """
        subtab_class = self.tabs_info.get(tab_name)
        if subtab_class:
            subtab_instance = subtab_class(self.auth_manager, self.main_tab_widget)
            return (tab_name, subtab_instance)
        else:
            raise Exception(f"No subtab class found for {tab_name}")

    def on_subtab_loaded(self, result):
        """
        Handle the loaded subtab.
        """
        tab_name, subtab_instance = result
        index = self.sub_tab_widget.indexOf(subtab_instance)
        if index == -1:
            # Find the placeholder index
            index = self.sub_tab_widget.indexOf(self.sub_tab_widget.findChild(QWidget, "Loading..."))
        if index != -1:
            self.loaded_tabs[tab_name] = subtab_instance
            self.sub_tab_widget.removeTab(index)
            self.sub_tab_widget.insertTab(index, subtab_instance, tab_name)
            self.sub_tab_widget.setCurrentIndex(index)

    def on_error(self, error_tuple):
        """
        Handle errors from worker threads.
        """
        if len(error_tuple) == 2:
            returncode, stderr = error_tuple
            QMessageBox.critical(self, "Error", f"Error (Return Code: {returncode}):\n{stderr}")
        elif len(error_tuple) == 3:
            exctype, value, traceback_str = error_tuple
            QMessageBox.critical(self, "Error", f"Error: {value}\n{traceback_str}")
        else:
            QMessageBox.critical(self, "Error", "An unknown error occurred.")