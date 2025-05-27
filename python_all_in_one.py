from multiprocessing import Process
import subprocess
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

class FileProcessor:
    def __init__(self, filename):
        self.filename = filename  # attribute

    def read_file(self):  # method
        with open(self.filename, 'r') as f:
            return f.read()

    def write_output(self, content):
        with open("output.txt", "w") as f:
            f.write(content)

def run_subprocess():
    subprocess.Popen(["echo", "Hello from subprocess"])

def run_fork():
    pid = os.fork()
    if pid == 0:
        print("Child process running")
    else:
        print("Parent process continuing")

def process_task():
    print("Running in new multiprocessing process")

@app.route("/process", methods=["POST"])
def api_process_file():
    data = request.json
    processor = FileProcessor(data["filename"])
    content = processor.read_file()
    processor.write_output(content.upper())
    return jsonify({"status": "processed"})

if __name__ == "__main__":
    p = Process(target=process_task)
    p.start()

    run_subprocess()
    run_fork()

    app.run(port=5000)
