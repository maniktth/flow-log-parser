import java.io.*;
import java.util.*;

public class FlowLogParser {
    private static final String UNTAGGED = "Untagged";
    private static final Map<Integer, String> PROTOCOL_MAP;
    static {
        Map<Integer, String> map = new HashMap<>();
        map.put(1, "icmp");
        map.put(6, "tcp");
        map.put(17, "udp");
        map.put(2, "igmp");
        map.put(50, "esp");
        map.put(89, "ospf");
        PROTOCOL_MAP = Collections.unmodifiableMap(map);
    }

    public static void main(String[] args) {
        String lookupTablePath = "lookup_table.csv";
        String flowLogPath = "vpc_flow_logs.txt";
        String resultOutputPath = "output_results.txt";

        try {
            Map<PortProtocol, String> tagMapping = readLookupTable(lookupTablePath);
            ProcessResult result = processFlowLogs(flowLogPath, tagMapping);
            outputResultsToFile(result, resultOutputPath);
            System.out.println("Processing completed successfully. Results written to " + resultOutputPath);
        } catch (IOException e) {
            System.err.println("Error processing files: " + e.getMessage());
        }
    }

    private static Map<PortProtocol, String> readLookupTable(String filePath) throws IOException {
        Map<PortProtocol, String> tagMapping = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            reader.readLine(); // Skip header
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 3) {
                    int port = Integer.parseInt(parts[0]);
                    String protocol = parts[1].trim().toLowerCase();
                    String tag = parts[2].trim();
                    if (protocol.equals("tcp")) {
                        protocol = "6";
                    } else if (protocol.equals("udp")) {
                        protocol = "17";
                    } else if (protocol.equals("icmp")) {
                        protocol = "1";
                    }
                    tagMapping.put(new PortProtocol(port, protocol), tag);
                }
            }
        }
        return tagMapping;
    }

    private static ProcessResult processFlowLogs(String logFilePath, Map<PortProtocol, String> tagMapping) throws IOException {
        Map<String, Integer> tagCounters = new HashMap<>();
        Map<PortProtocol, Integer> portProtocolCounters = new HashMap<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(logFilePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] columns = line.split("\\s+");
                if (columns.length >= 8) {
                    try {
                        int destinationPort = Integer.parseInt(columns[5]);
                        String protocolNumber = columns[7];
                        String protocolName = PROTOCOL_MAP.getOrDefault(Integer.parseInt(protocolNumber), "unknown");

                        PortProtocol portProtocol = new PortProtocol(destinationPort, protocolNumber);
                        String assignedTag = tagMapping.getOrDefault(portProtocol, UNTAGGED);

                        tagCounters.merge(assignedTag, 1, Integer::sum);
                        portProtocolCounters.merge(new PortProtocol(destinationPort, protocolName), 1, Integer::sum);
                    } catch (NumberFormatException e) {
                        System.err.println("Error parsing line: " + line);
                        System.err.println("Error details: " + e.getMessage());
                    }
                } else {
                    System.err.println("Invalid line format: " + line);
                }
            }
        }

        return new ProcessResult(tagCounters, portProtocolCounters);
    }

    private static void outputResultsToFile(ProcessResult result, String outputFilePath) throws IOException {
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFilePath))) {
            writer.println("Tag Counts:");
            writer.println("Tag,Count");
            result.tagCounters.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> writer.println(entry.getKey() + "," + entry.getValue()));

            writer.println("\nPort/Protocol Combination Counts:");
            writer.println("Port,Protocol,Count");
            result.portProtocolCounters.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> writer.println(entry.getKey().port + "," + entry.getKey().protocol + "," + entry.getValue()));
        }
    }

    private static class PortProtocol implements Comparable<PortProtocol> {
        final int port;
        final String protocol;

        PortProtocol(int port, String protocol) {
            this.port = port;
            this.protocol = protocol;
        }

        @Override
        public int compareTo(PortProtocol other) {
            int portCompare = Integer.compare(this.port, other.port);
            if (portCompare != 0) {
                return portCompare;
            }
            return this.protocol.compareTo(other.protocol);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PortProtocol that = (PortProtocol) o;
            return port == that.port && Objects.equals(protocol, that.protocol);
        }

        @Override
        public int hashCode() {
            return Objects.hash(port, protocol);
        }

        @Override
        public String toString() {
            return port + "," + protocol;
        }
    }

    private static class ProcessResult {
        final Map<String, Integer> tagCounters;
        final Map<PortProtocol, Integer> portProtocolCounters;

        ProcessResult(Map<String, Integer> tagCounters, Map<PortProtocol, Integer> portProtocolCounters) {
            this.tagCounters = tagCounters;
            this.portProtocolCounters = portProtocolCounters;
        }
    }
}