#include <iostream>
#include <fstream>
#include <unistd.h>

class FileHandler {
public:
    std::string filename;
    FileHandler(std::string fname) : filename(fname) {}

    void readFile() {
        std::ifstream file(filename);
        std::string line;
        while (getline(file, line)) {
            std::cout << line << std::endl;  // output event
        }
    }
};

void forkProcess() {
    pid_t pid = fork();
    if (pid == 0) {
        std::cout << "Child process running in C++\n";
    } else {
        std::cout << "Parent process in C++\n";
    }
}

int main() {
    std::string fname;
    std::cout << "Enter file name: ";
    std::cin >> fname;  // input event

    FileHandler fh(fname);
    fh.readFile();

    forkProcess();

    return 0;
}
