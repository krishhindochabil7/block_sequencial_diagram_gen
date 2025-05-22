#include <SimpleAmqpClient/SimpleAmqpClient.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <mutex>

using namespace AmqpClient;
using json = nlohmann::json;

// User data structures
std::unordered_map<std::string, std::string> users; // username: password
std::unordered_map<std::string, std::string> sessions; // correlation_id: username
std::unordered_map<std::string, std::string> connected_users; // username: reply_to

std::mutex data_mutex; // Mutex for thread safety

void handle_request(Channel::ptr_t channel, const Envelope::ptr_t& envelope) {
    std::string body = envelope->Message()->Body();
    std::string correlation_id = envelope->Message()->CorrelationId();
    std::string reply_to = envelope->Message()->ReplyTo();

    json response;
    try {
        json request = json::parse(body);
        std::string action = request.value("action", "");

        std::lock_guard<std::mutex> lock(data_mutex); // Ensure thread safety

        if (action == "register") {
            std::string username = request.value("username", "");
            std::string password = request.value("password", "");

            if (users.find(username) != users.end()) {
                response = {{"status", "error"}, {"message", "User already exists"}};
            } else {
                users[username] = password;
                response = {{"status", "success"}, {"message", "Registration successful"}};
            }
        } else if (action == "login") {
            std::string username = request.value("username", "");
            std::string password = request.value("password", "");

            if (users.find(username) != users.end() && users[username] == password) {
                sessions[correlation_id] = username;
                connected_users[username] = reply_to;
                response = {{"status", "success"}, {"message", "Login successful"}};
            } else {
                response = {{"status", "error"}, {"message", "Invalid credentials"}};
            }
        } else if (action == "access_service") {
            if (sessions.find(correlation_id) != sessions.end()) {
                std::string username = sessions[correlation_id];
                std::string service = request.value("service", "");

                if (service == "service1") {
                    response = {{"status", "success"}, {"result", "Result of service 1 for " + username}};
                } else if (service == "service2") {
                    response = {{"status", "success"}, {"result", "Result of service 2 for " + username}};
                } else {
                    response = {{"status", "error"}, {"message", "Unknown service"}};
                }
            } else {
                response = {{"status", "error"}, {"message", "Unauthorized"}};
            }
        } else {
            response = {{"status", "error"}, {"message", "Unknown action"}};
        }
    } catch (const std::exception& e) {
        response = {{"status", "error"}, {"message", std::string("Exception: ") + e.what()}};
    }

    // Send the response
    BasicMessage::ptr_t response_msg = BasicMessage::Create(response.dump());
    response_msg->CorrelationId(correlation_id);
    channel->BasicPublish("", reply_to, response_msg);
}

void periodic_updates(Channel::ptr_t channel) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));

        std::lock_guard<std::mutex> lock(data_mutex); // Ensure thread safety

        for (const auto& [username, reply_to] : connected_users) {
            json message = {
                {"event", "server_update"},
                {"message", "Hello " + username + ", here's a periodic update!"}
            };

            BasicMessage::ptr_t msg = BasicMessage::Create(message.dump());
            channel->BasicPublish("", reply_to, msg);
        }
    }
}

int main() {
    try {
        Channel::ptr_t channel = Channel::Create("localhost");

        // Declare the RPC queue
        std::string queue_name = "rpc_queue";
        channel->DeclareQueue(queue_name, false, true, false, false);

        // Start consuming messages
        std::string consumer_tag = channel->BasicConsume(queue_name, "", true, false, false);

        // Start the periodic updates thread
        std::thread periodic_thread(periodic_updates, channel);

        std::cout << "RabbitMQ RPC server started..." << std::endl;

        while (true) {
            Envelope::ptr_t envelope = channel->BasicConsumeMessage(consumer_tag);
            handle_request(channel, envelope);
        }

        // Join the periodic thread before exiting (not reachable in this example)
        periodic_thread.join();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}
