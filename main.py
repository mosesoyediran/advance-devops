import os
import sys
import time

from PyQt5.QtWidgets import QApplication
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from sign_in_window import SignInWindow


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, restart_callback):
        self.restart_callback = restart_callback

    def on_modified(self, event):
        if event.src_path.endswith('.py'):
            print(f"Detected change in {event.src_path}. Restarting application...")
            self.restart_callback()
            
            
def restart_application():
        QApplication.quit()
        time.sleep(1)  # Give the application some time to quit
        os.execl(sys.executable, sys.executable, *sys.argv)  # Restart the app


def main():
    app = QApplication(sys.argv)
    sign_in_window = SignInWindow()
    sign_in_window.show()

    # Set up file watching using watchdoga
    observer = Observer()
    event_handler = FileChangeHandler(restart_callback=restart_application)
    observer.schedule(event_handler, '.', recursive=True)  # Watch the current directory for changes
    observer.start()

    try:
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Error: {e}")
        observer.stop()

    observer.join()

if __name__ == '__main__':
    main()
