# base_subtab.py

import subprocess
import sys
import traceback

from PyQt5.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal
from PyQt5.QtWidgets import QMessageBox, QTextEdit, QWidget


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
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()

class BaseSubtab(QWidget):
    """
    Base class for all Kubernetes management subtabs.
    """
    def __init__(self, auth_manager, main_tab_widget):
        super().__init__()
        self.auth_manager = auth_manager
        self.main_tab_widget = main_tab_widget
        self.threadpool = QThreadPool()
        self.initUI()

    def initUI(self):
        """
        Initialize the UI components.
        To be overridden by subclasses.
        """
        pass

    def handle_error(self, error_tuple):
        """
        Handle errors emitted by worker threads.
        """
        if len(error_tuple) == 2:
            returncode, stderr = error_tuple
            QMessageBox.critical(self, "Error", f"Error (Return Code: {returncode}):\n{stderr}")
            self.append_output(f"Error (Return Code: {returncode}):\n{stderr}")
        elif len(error_tuple) == 3:
            exctype, value, traceback_str = error_tuple
            QMessageBox.critical(self, "Error", f"Error: {value}\n{traceback_str}")
            self.append_output(f"Error: {value}\n{traceback_str}")
        else:
            QMessageBox.critical(self, "Error", "An unknown error occurred.")
            self.append_output("An unknown error occurred.")

    def append_output(self, message):
        """
        Append a message to the command output QTextEdit.
        To be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method.")
