#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void run_fork() {
    pid_t pid = fork();
    if (pid == 0) {
        printf("Child process created using fork()\n");
    } else {
        printf("Parent process with PID: %d\n", getpid());
    }
}

void run_exec() {
    execl("/bin/echo", "echo", "Hello from exec!", NULL);
}

int main() {
    char filename[50];
    printf("Enter filename: ");
    scanf("%s", filename); // input event

    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("File open error");
        return 1;
    }

    char line[100];
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line); // output event
    }
    fclose(fp);

    run_fork();
    // run_exec(); // Uncomment to replace process

    return 0;
}
