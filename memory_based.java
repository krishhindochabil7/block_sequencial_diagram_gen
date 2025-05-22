import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.*;
import com.google.gson.*;

public class MultiClientServer {

    private static final Map<Integer, String> sharedRequests = new ConcurrentHashMap<>();
    private static final Map<Integer, String> sharedResponses = new ConcurrentHashMap<>();
    private static final Lock lock = new ReentrantLock();
    private static final Condition condition = lock.newCondition();
    private static final Gson gson = new Gson();

    public static void main(String[] args) {
        Server server = new Server();
        Thread serverThread = new Thread(server);
        serverThread.start();

        // Example Clients
        new Thread(new Client(1, createRequest("register", "alice", "pass123", null))).start();
        sleep(100); // small wait to simulate real-world sequence
        new Thread(new Client(2, createRequest("login", "alice", "pass123", null))).start();
        sleep(100);
        new Thread(new Client(2, createRequest("access_service", null, null, "service1"))).start();

        // Stop server after some time
        sleep(2000);
        server.stop();
    }

    private static Map<String, String> createRequest(String action, String username, String password, String service) {
        Map<String, String> request = new HashMap<>();
        request.put("action", action);
        if (username != null) request.put("username", username);
        if (password != null) request.put("password", password);
        if (service != null) request.put("service", service);
        return request;
    }

    static class Server implements Runnable {
        private final Map<String, String> users = new ConcurrentHashMap<>();
        private final Map<Integer, String> sessions = new ConcurrentHashMap<>();
        private final Map<String, Integer> connectedUsers = new ConcurrentHashMap<>();
        private volatile boolean running = true;

        @Override
        public void run() {
            while (running) {
                lock.lock();
                try {
                    condition.await(500, TimeUnit.MILLISECONDS);

                    for (Integer clientId : new HashSet<>(sharedRequests.keySet())) {
                        String message = sharedRequests.remove(clientId);
                        Map<String, String> data = gson.fromJson(message, Map.class);
                        String action = data.get("action");
                        Map<String, String> response = new HashMap<>();

                        try {
                            switch (action) {
                                case "register":
                                    String regUser = data.get("username");
                                    String regPass = data.get("password");
                                    if (users.containsKey(regUser)) {
                                        response.put("status", "error");
                                        response.put("message", "User already exists");
                                    } else {
                                        users.put(regUser, regPass);
                                        response.put("status", "success");
                                        response.put("message", "Registration successful");
                                    }
                                    break;

                                case "login":
                                    String logUser = data.get("username");
                                    String logPass = data.get("password");
                                    if (logPass.equals(users.get(logUser))) {
                                        sessions.put(clientId, logUser);
                                        connectedUsers.put(logUser, clientId);
                                        response.put("status", "success");
                                        response.put("message", "Login successful");
                                    } else {
                                        response.put("status", "error");
                                        response.put("message", "Invalid credentials");
                                    }
                                    break;

                                case "access_service":
                                    String username = sessions.get(clientId);
                                    if (username == null) {
                                        response.put("status", "error");
                                        response.put("message", "Unauthorized");
                                    } else {
                                        String service = data.get("service");
                                        if ("service1".equals(service)) {
                                            response.put("status", "success");
                                            response.put("result", "Result of service 1 for " + username);
                                        } else if ("service2".equals(service)) {
                                            response.put("status", "success");
                                            response.put("result", "Result of service 2 for " + username);
                                        } else {
                                            response.put("status", "error");
                                            response.put("message", "Unknown service");
                                        }
                                    }
                                    break;

                                default:
                                    response.put("status", "error");
                                    response.put("message", "Unknown action");
                            }

                        } catch (Exception e) {
                            response.put("status", "error");
                            response.put("message", "Exception: " + e.getMessage());
                        }

                        sharedResponses.put(clientId, gson.toJson(response));
                    }

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    lock.unlock();
                }
            }
        }

        public void stop() {
            running = false;
        }
    }

    static class Client implements Runnable {
        private final int clientId;
        private final Map<String, String> request;

        public Client(int clientId, Map<String, String> request) {
            this.clientId = clientId;
            this.request = request;
        }

        @Override
        public void run() {
            String jsonRequest = gson.toJson(request);

            lock.lock();
            try {
                sharedRequests.put(clientId, jsonRequest);
                condition.signalAll();
            } finally {
                lock.unlock();
            }

            // Wait for response
            while (!sharedResponses.containsKey(clientId)) {
                sleep(100);
            }

            String response = sharedResponses.remove(clientId);
            System.out.println("Client " + clientId + " received: " + response);
        }
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
