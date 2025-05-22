#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <cjson/cJSON.h>

#define PORT 8765
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

typedef struct {
    char username[50];
    char password[50];
    int socket_fd;
    bool logged_in;
} User;

User users[MAX_CLIENTS];
int user_count = 0;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void send_json(int sockfd, cJSON *json) {
    char *data = cJSON_PrintUnformatted(json);
    send(sockfd, data, strlen(data), 0);
    send(sockfd, "\n", 1, 0);
    free(data);
}

void broadcast_periodic() {
    while (1) {
        sleep(10);
        pthread_mutex_lock(&lock);
        for (int i = 0; i < user_count; ++i) {
            if (users[i].logged_in) {
                cJSON *msg = cJSON_CreateObject();
                cJSON_AddStringToObject(msg, "event", "server_update");

                char update[100];
                snprintf(update, sizeof(update), "Hello %s, here's a periodic update!", users[i].username);
                cJSON_AddStringToObject(msg, "message", update);
                send_json(users[i].socket_fd, msg);
                cJSON_Delete(msg);
            }
        }
        pthread_mutex_unlock(&lock);
    }
}

void *handle_client(void *arg) {
    int sockfd = *(int *)arg;
    char buffer[BUFFER_SIZE];
    int n;

    while ((n = recv(sockfd, buffer, sizeof(buffer)-1, 0)) > 0) {
        buffer[n] = '\0';
        cJSON *json = cJSON_Parse(buffer);
        if (!json) continue;

        const char *action = cJSON_GetObjectItem(json, "action")->valuestring;

        if (strcmp(action, "register") == 0) {
            const char *username = cJSON_GetObjectItem(json, "username")->valuestring;
            const char *password = cJSON_GetObjectItem(json, "password")->valuestring;

            pthread_mutex_lock(&lock);
            bool exists = false;
            for (int i = 0; i < user_count; ++i) {
                if (strcmp(users[i].username, username) == 0) {
                    exists = true;
                    break;
                }
            }

            cJSON *reply = cJSON_CreateObject();
            if (exists) {
                cJSON_AddStringToObject(reply, "status", "error");
                cJSON_AddStringToObject(reply, "message", "User already exists");
            } else {
                strncpy(users[user_count].username, username, 50);
                strncpy(users[user_count].password, password, 50);
                users[user_count].socket_fd = sockfd;
                users[user_count].logged_in = false;
                user_count++;

                cJSON_AddStringToObject(reply, "status", "success");
                cJSON_AddStringToObject(reply, "message", "Registration successful");
            }
            send_json(sockfd, reply);
            cJSON_Delete(reply);
            pthread_mutex_unlock(&lock);

        } else if (strcmp(action, "login") == 0) {
            const char *username = cJSON_GetObjectItem(json, "username")->valuestring;
            const char *password = cJSON_GetObjectItem(json, "password")->valuestring;

            pthread_mutex_lock(&lock);
            bool valid = false;
            for (int i = 0; i < user_count; ++i) {
                if (strcmp(users[i].username, username) == 0 &&
                    strcmp(users[i].password, password) == 0) {
                    users[i].logged_in = true;
                    users[i].socket_fd = sockfd;
                    valid = true;
                    break;
                }
            }
            cJSON *reply = cJSON_CreateObject();
            if (valid) {
                cJSON_AddStringToObject(reply, "status", "success");
                cJSON_AddStringToObject(reply, "message", "Login successful");
            } else {
                cJSON_AddStringToObject(reply, "status", "error");
                cJSON_AddStringToObject(reply, "message", "Invalid credentials");
            }
            send_json(sockfd, reply);
            cJSON_Delete(reply);
            pthread_mutex_unlock(&lock);

        } else if (strcmp(action, "access_service") == 0) {
            const char *service = cJSON_GetObjectItem(json, "service")->valuestring;
            pthread_mutex_lock(&lock);
            char *username = NULL;
            for (int i = 0; i < user_count; ++i) {
                if (users[i].socket_fd == sockfd && users[i].logged_in) {
                    username = users[i].username;
                    break;
                }
            }
            cJSON *reply = cJSON_CreateObject();
            if (!username) {
                cJSON_AddStringToObject(reply, "status", "error");
                cJSON_AddStringToObject(reply, "message", "Unauthorized");
            } else if (strcmp(service, "service1") == 0 || strcmp(service, "service2") == 0) {
                cJSON_AddStringToObject(reply, "status", "success");
                char result[100];
                snprintf(result, sizeof(result), "Result of %s for %s", service, username);
                cJSON_AddStringToObject(reply, "result", result);
            } else {
                cJSON_AddStringToObject(reply, "status", "error");
                cJSON_AddStringToObject(reply, "message", "Unknown service");
            }
            send_json(sockfd, reply);
            cJSON_Delete(reply);
            pthread_mutex_unlock(&lock);
        }

        cJSON_Delete(json);
    }

    close(sockfd);
    return NULL;
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addrlen = sizeof(client_addr);

    pthread_t tid, broadcaster;
    pthread_create(&broadcaster, NULL, (void *)broadcast_periodic, NULL);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, MAX_CLIENTS);

    printf("TCP Server started on port %d\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
        pthread_create(&tid, NULL, handle_client, &client_fd);
        sleep(1); // prevent race with thread using same arg
    }

    return 0;
}
