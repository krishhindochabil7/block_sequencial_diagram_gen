import java.io.*;

class FileHandler {
    private String filename;

    public FileHandler(String filename) {
        this.filename = filename;
    }

    public void readFile() throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(filename));
        String line;
        while((line = reader.readLine()) != null) {
            System.out.println(line); // output event
        }
        reader.close();
    }
}

public class Main {
    public static void main(String[] args) {
        try {
            System.out.print("Enter filename: ");
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in)); // input event
            String filename = input.readLine();

            FileHandler fh = new FileHandler(filename);
            fh.readFile();

            ProcessBuilder pb = new ProcessBuilder("echo", "Hello from ProcessBuilder");
            Process process = pb.start(); // process creation

            BufferedReader output = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = output.readLine()) != null) {
                System.out.println("Subprocess output: " + line);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
