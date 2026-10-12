import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.Month;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.function.Consumer;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

public class Log {
    private static final Pattern SYSLOG_LINE = Pattern.compile(
            "^(?:<(\\d+)>)?(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+(.*)$");
    private static final Pattern ISO_LINE = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})?)\\s+(.*)$");
    private static final Pattern PROCESS_PREFIX = Pattern.compile("^([^:\\s\\[]+(?:\\[\\d+])?):\\s*(.*)$");
    private static final Pattern IP_ADDRESS = Pattern.compile(
            "(?:\\bfrom\\s+|\\brhost=)([0-9a-fA-F:.]+)");
    private static final DateTimeFormatter SYSLOG_TIME =
            DateTimeFormatter.ofPattern("MMM d HH:mm:ss", Locale.ENGLISH);
    private Log() {
    }

    public static void main(String[] args) {
        try {
            Options options = Options.parse(args);
            if (options.help) {
                printUsage();
                return;
            }
            if (options.input == null) {
                options.input = promptForInput();
                if (options.input == null) {
                    printUsage();
                    return;
                }
            }
            if (!Files.isRegularFile(options.input)) {
                throw new IOException("Input file does not exist or is not a regular file: " + options.input);
            }

            String format = detectFormat(options.input, options.format);
            Analyzer analyzer = new Analyzer(options.threshold, options.windowMinutes);
            LogParser parser = format.equals("windows-xml") ? new WindowsXmlParser() : new LinuxParser();
            parser.parse(options.input, analyzer::accept);
            analyzer.printSummary(options.input, format);

            if (options.jsonOutput != null) {
                Files.writeString(options.jsonOutput, analyzer.toJson(options.input, format));
                System.out.println("JSON report written to " + options.jsonOutput.toAbsolutePath());
            }
        } catch (IllegalArgumentException | IOException e) {
            System.err.println("Error: " + e.getMessage());
            System.err.println("Use --help to see supported options.");
            System.exit(2);
        }
    }

    private static Path promptForInput() throws IOException {
        System.out.print("Enter the path to a log file (or press Enter to exit): ");
        System.out.flush();
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
        String line = input.readLine();
        if (line == null || line.isBlank()) {
            return null;
        }
        String path = line.trim();
        if (path.length() >= 2
                && ((path.startsWith("\"") && path.endsWith("\""))
                || (path.startsWith("'") && path.endsWith("'")))) {
            path = path.substring(1, path.length() - 1);
        }
        return Path.of(path);
    }

    private static String detectFormat(Path input, String requested) throws IOException {
        if (!requested.equals("auto")) {
            return requested;
        }
        if (input.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".xml")) {
            return "windows-xml";
        }
        try (BufferedReader reader = Files.newBufferedReader(input)) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.stripLeading();
                if (!trimmed.isEmpty()) {
                    return trimmed.startsWith("<") ? "windows-xml" : "linux";
                }
            }
        }
        return "linux";
    }

    private static void printUsage() {
        System.out.println("""
                Java Log Analyzer
                Usage: java Log <input-file> [options]

                Options:
                  --format <auto|linux|windows-xml>  Input format (default: auto)
                  --threshold <count>               SSH failures to flag (default: 5)
                  --window-minutes <minutes>        Detection window (default: 10)
                  --json <output-file>              Write a JSON summary report
                  --help                            Show this help

                Examples:
                  java Log /var/log/auth.log
                  java Log exported-events.xml --format windows-xml --json report.json
                """);
    }

    private interface LogParser {
        void parse(Path path, Consumer<LogEntry> consumer) throws IOException;
    }

    private static final class LinuxParser implements LogParser {
        @Override
        public void parse(Path path, Consumer<LogEntry> consumer) throws IOException {
            try (BufferedReader reader = Files.newBufferedReader(path)) {
                String rawLine;
                while ((rawLine = reader.readLine()) != null) {
                    if (rawLine.startsWith("\uFEFF")) {
                        rawLine = rawLine.substring(1);
                    }
                    consumer.accept(parseLinuxLine(rawLine));
                }
            }
        }

        private LogEntry parseLinuxLine(String rawLine) {
            Matcher syslog = SYSLOG_LINE.matcher(rawLine);
            if (syslog.matches()) {
                LocalDateTime timestamp = parseSyslogTimestamp(syslog.group(2));
                String message = syslog.group(4);
                String source = syslog.group(3);
                Matcher process = PROCESS_PREFIX.matcher(message);
                if (process.matches()) {
                    source = process.group(1);
                    message = process.group(2);
                }
                LogLevel level = syslog.group(1) == null
                        ? detectLevel(message)
                        : levelFromPriority(Integer.parseInt(syslog.group(1)));
                return new LogEntry(timestamp, level, source, message, rawLine,
                        classify(source, message));
            }

            Matcher iso = ISO_LINE.matcher(rawLine);
            if (iso.matches()) {
                String tail = iso.group(2);
                String source = "unknown";
                String message = tail;
                Matcher process = PROCESS_PREFIX.matcher(tail);
                if (process.matches()) {
                    source = process.group(1);
                    message = process.group(2);
                }
                return new LogEntry(parseTimestamp(iso.group(1)), detectLevel(message), source,
                        message, rawLine, classify(source, message));
            }

            return new LogEntry(null, detectLevel(rawLine), "unknown", rawLine, rawLine,
                    classify("unknown", rawLine));
        }

        private LocalDateTime parseSyslogTimestamp(String value) {
            LocalDate today = LocalDate.now();
            try {
                var parsed = SYSLOG_TIME.parse(value);
                LocalDateTime candidate = LocalDateTime.of(today.getYear(),
                        Month.from(parsed),
                        parsed.get(ChronoField.DAY_OF_MONTH),
                        parsed.get(ChronoField.HOUR_OF_DAY),
                        parsed.get(ChronoField.MINUTE_OF_HOUR),
                        parsed.get(ChronoField.SECOND_OF_MINUTE));
                if (candidate.isAfter(LocalDateTime.now().plusDays(1))) {
                    candidate = candidate.minusYears(1);
                }
                return candidate;
            } catch (DateTimeParseException e) {
                return null;
            }
        }
    }

    private static final class WindowsXmlParser implements LogParser {
        @Override
        public void parse(Path path, Consumer<LogEntry> consumer) throws IOException {
            XMLInputFactory factory = XMLInputFactory.newFactory();
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
            factory.setXMLResolver((publicId, systemId, baseUri, namespace) -> {
                throw new XMLStreamException("External XML entities are not allowed");
            });

            try (var input = Files.newInputStream(path)) {
                XMLStreamReader reader = factory.createXMLStreamReader(input);
                try {
                    while (reader.hasNext()) {
                        if (reader.next() == XMLStreamConstants.START_ELEMENT
                                && reader.getLocalName().equals("Event")) {
                            consumer.accept(readEvent(reader));
                        }
                    }
                } finally {
                    reader.close();
                }
            } catch (XMLStreamException e) {
                throw new IOException("Unable to parse Windows event XML: " + e.getMessage(), e);
            }
        }

        private LogEntry readEvent(XMLStreamReader reader) throws XMLStreamException {
            int depth = 1;
            String timestamp = null;
            String provider = "Windows";
            String eventId = null;
            String levelValue = null;
            String renderingMessage = null;
            StringBuilder message = new StringBuilder();
            String activeElement = null;
            String activeDataName = null;
            StringBuilder text = new StringBuilder();

            while (depth > 0 && reader.hasNext()) {
                int token = reader.next();
                if (token == XMLStreamConstants.START_ELEMENT) {
                    depth++;
                    activeElement = reader.getLocalName();
                    text.setLength(0);
                    if (activeElement.equals("Provider")) {
                        String name = reader.getAttributeValue(null, "Name");
                        if (name != null && !name.isBlank()) {
                            provider = name;
                        }
                    } else if (activeElement.equals("TimeCreated")) {
                        timestamp = reader.getAttributeValue(null, "SystemTime");
                    } else if (activeElement.equals("Data")) {
                        activeDataName = reader.getAttributeValue(null, "Name");
                    }
                } else if (token == XMLStreamConstants.CHARACTERS
                        || token == XMLStreamConstants.CDATA) {
                    if (activeElement != null) {
                        text.append(reader.getText());
                    }
                } else if (token == XMLStreamConstants.END_ELEMENT) {
                    String ended = reader.getLocalName();
                    if (ended.equals("EventID")) {
                        eventId = text.toString().trim();
                    } else if (ended.equals("Level")) {
                        levelValue = text.toString().trim();
                    } else if (ended.equals("Message")) {
                        renderingMessage = text.toString().trim();
                    } else if (ended.equals("Data")) {
                        String value = text.toString().trim();
                        if (!value.isEmpty()) {
                            if (message.length() > 0) {
                                message.append("; ");
                            }
                            if (activeDataName != null && !activeDataName.isBlank()) {
                                message.append(activeDataName).append('=');
                            }
                            message.append(value);
                        }
                        activeDataName = null;
                    }
                    if (ended.equals(activeElement)) {
                        activeElement = null;
                    }
                    depth--;
                }
            }

            String eventMessage = renderingMessage;
            if (eventMessage == null || eventMessage.isBlank()) {
                eventMessage = message.toString();
            }
            if (eventMessage.isBlank()) {
                eventMessage = "Windows event " + (eventId == null ? "unknown" : eventId);
            }
            if (eventId != null && !eventId.isBlank()) {
                eventMessage = "[Event " + eventId + "] " + eventMessage;
            }
            LocalDateTime parsedTimestamp = timestamp == null ? null : parseTimestamp(timestamp);
            LogLevel level = levelValue == null ? detectLevel(eventMessage)
                    : windowsLevel(levelValue);
            return new LogEntry(parsedTimestamp, level, provider, eventMessage,
                    eventMessage, classify(provider, eventMessage));
        }
    }

    private static LocalDateTime parseTimestamp(String value) {
        try {
            return OffsetDateTime.parse(value).toLocalDateTime();
        } catch (DateTimeParseException ignored) {
            try {
                return LocalDateTime.parse(value, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            } catch (DateTimeParseException ignoredAgain) {
                String normalized = value.replace(' ', 'T');
                try {
                    return LocalDateTime.parse(normalized, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                } catch (DateTimeParseException ignoredThird) {
                    return null;
                }
            }
        }
    }

    private static LogLevel levelFromPriority(int priority) {
        return switch (priority & 7) {
            case 0, 1 -> LogLevel.CRITICAL;
            case 2, 3 -> LogLevel.ERROR;
            case 4 -> LogLevel.WARNING;
            case 5, 6 -> LogLevel.INFO;
            default -> LogLevel.DEBUG;
        };
    }

    private static LogLevel windowsLevel(String value) {
        return switch (value) {
            case "1" -> LogLevel.CRITICAL;
            case "2" -> LogLevel.ERROR;
            case "3" -> LogLevel.WARNING;
            case "4" -> LogLevel.INFO;
            case "5" -> LogLevel.DEBUG;
            default -> detectLevel(value);
        };
    }

    private static LogLevel detectLevel(String text) {
        String upper = text.toUpperCase(Locale.ROOT);
        if (upper.matches(".*\\b(EMERG|EMERGENCY|ALERT|CRITICAL|CRIT|FATAL)\\b.*")) {
            return LogLevel.CRITICAL;
        }
        if (upper.matches(".*\\b(ERROR|ERR|FAILED|FAILURE)\\b.*")) {
            return LogLevel.ERROR;
        }
        if (upper.matches(".*\\b(WARNING|WARN)\\b.*")) {
            return LogLevel.WARNING;
        }
        if (upper.matches(".*\\b(DEBUG|TRACE)\\b.*")) {
            return LogLevel.DEBUG;
        }
        return LogLevel.INFO;
    }

    private static Category classify(String source, String message) {
        String text = (source + " " + message).toLowerCase(Locale.ROOT);
        if (text.matches(".*(failed password|authentication failure|invalid user|login failed|logon failure|failed login).*")) {
            return Category.AUTH_FAILURE;
        }
        if (text.matches(".*(accepted password|accepted publickey|session opened|login successful|logon successful|authentication success).*")) {
            return Category.AUTH_SUCCESS;
        }
        if (text.matches(".*(sudo|su:|privilege escalation|unauthorized|exploit|intrusion|suspicious).*")) {
            return Category.SECURITY_ALERT;
        }
        if (text.matches(".*(dhcp|firewall|ssh|network|connection|interface).*")) {
            return Category.NETWORK;
        }
        if (text.matches(".*(kernel|boot|shutdown|reboot|systemd|service).*")) {
            return Category.SYSTEM;
        }
        return Category.APPLICATION;
    }

    private enum LogLevel {
        CRITICAL, ERROR, WARNING, INFO, DEBUG
    }

    private enum Category {
        AUTH_FAILURE, AUTH_SUCCESS, SECURITY_ALERT, SYSTEM, NETWORK, APPLICATION
    }

    private record LogEntry(LocalDateTime timestamp, LogLevel level, String source,
                            String message, String rawLine, Category category) {
    }

    private record Alert(LocalDateTime timestamp, String type, int count, String source) {
    }

    private static final class Analyzer {
        private final int threshold;
        private final int windowMinutes;
        private final EnumMap<Category, Long> categories = new EnumMap<>(Category.class);
        private final EnumMap<LogLevel, Long> levels = new EnumMap<>(LogLevel.class);
        private final Map<String, Long> sources = new HashMap<>();
        private final Map<Integer, Long> hours = new HashMap<>();
        private final Map<Integer, Long> errorsByHour = new HashMap<>();
        private final Map<String, Deque<LocalDateTime>> failedLogins = new HashMap<>();
        private final Map<String, Boolean> alerted = new HashMap<>();
        private final List<Alert> alerts = new ArrayList<>();
        private long total;
        private long authenticationSuccesses;
        private long authenticationFailures;

        Analyzer(int threshold, int windowMinutes) {
            this.threshold = threshold;
            this.windowMinutes = windowMinutes;
            for (Category category : Category.values()) {
                categories.put(category, 0L);
            }
            for (LogLevel level : LogLevel.values()) {
                levels.put(level, 0L);
            }
        }

        void accept(LogEntry entry) {
            total++;
            categories.merge(entry.category(), 1L, Long::sum);
            levels.merge(entry.level(), 1L, Long::sum);
            sources.merge(entry.source(), 1L, Long::sum);
            if (entry.timestamp() != null) {
                hours.merge(entry.timestamp().getHour(), 1L, Long::sum);
                if (entry.level() == LogLevel.CRITICAL || entry.level() == LogLevel.ERROR) {
                    errorsByHour.merge(entry.timestamp().getHour(), 1L, Long::sum);
                }
            }
            if (entry.category() == Category.AUTH_SUCCESS) {
                authenticationSuccesses++;
            } else if (entry.category() == Category.AUTH_FAILURE) {
                authenticationFailures++;
                detectBruteForce(entry);
            }
        }

        private void detectBruteForce(LogEntry entry) {
            if (entry.timestamp() == null) {
                return;
            }
            if (!(entry.source().toLowerCase(Locale.ROOT).contains("ssh")
                    || entry.message().toLowerCase(Locale.ROOT).contains("ssh"))) {
                return;
            }
            Matcher matcher = IP_ADDRESS.matcher(entry.message());
            String remote = matcher.find() ? matcher.group(1) : entry.source();
            Deque<LocalDateTime> attempts = failedLogins.computeIfAbsent(remote,
                    ignored -> new ArrayDeque<>());
            LocalDateTime cutoff = entry.timestamp().minus(windowMinutes, ChronoUnit.MINUTES);
            while (!attempts.isEmpty() && attempts.peekFirst().isBefore(cutoff)) {
                attempts.removeFirst();
            }
            attempts.addLast(entry.timestamp());
            if (attempts.size() >= threshold && !alerted.getOrDefault(remote, false)) {
                alerts.add(new Alert(entry.timestamp(), "BRUTE_FORCE_SSH", attempts.size(), remote));
                alerted.put(remote, true);
            } else if (attempts.size() < threshold) {
                alerted.remove(remote);
            }
        }

        void printSummary(Path input, String format) {
            System.out.println("Log analysis: " + input.toAbsolutePath());
            System.out.println("Format: " + format);
            System.out.println("Events analyzed: " + total);
            System.out.println("\nCategories:");
            categories.forEach((key, value) -> System.out.printf(Locale.ROOT, "  %-18s %d%n", key, value));
            System.out.println("\nLog levels:");
            levels.forEach((key, value) -> System.out.printf(Locale.ROOT, "  %-10s %d%n", key, value));
            System.out.printf("%nAuthentication: %d successes, %d failures%n",
                    authenticationSuccesses, authenticationFailures);
            if (!hours.isEmpty()) {
                int peak = hours.entrySet().stream()
                        .max(Map.Entry.comparingByValue())
                        .orElseThrow().getKey();
                System.out.printf("Peak activity hour: %02d:00 (%d events)%n", peak, hours.get(peak));
            }
            System.out.println("Errors by hour:");
            if (errorsByHour.isEmpty()) {
                System.out.println("  None");
            } else {
                errorsByHour.entrySet().stream()
                        .sorted(Map.Entry.comparingByKey())
                        .forEach(entry -> System.out.printf(Locale.ROOT, "  %02d:00 %d%n",
                                entry.getKey(), entry.getValue()));
            }
            System.out.println("\nTop sources:");
            sources.entrySet().stream()
                    .sorted(Map.Entry.<String, Long>comparingByValue().reversed()
                            .thenComparing(Map.Entry.comparingByKey()))
                    .limit(10)
                    .forEach(entry -> System.out.printf(Locale.ROOT, "  %-24s %d%n",
                            entry.getKey(), entry.getValue()));
            System.out.println("\nAlerts:");
            if (alerts.isEmpty()) {
                System.out.println("  None");
            } else {
                alerts.forEach(alert -> System.out.printf(Locale.ROOT,
                        "  %s %s count=%d source=%s%n",
                        alert.timestamp(), alert.type(), alert.count(), alert.source()));
            }
        }

        String toJson(Path input, String format) {
            StringBuilder json = new StringBuilder();
            json.append("{\n  \"input\": \"").append(jsonEscape(input.toString())).append("\",\n")
                    .append("  \"format\": \"").append(jsonEscape(format)).append("\",\n")
                    .append("  \"totalEvents\": ").append(total).append(",\n")
                    .append("  \"authentication\": {\"successes\": ").append(authenticationSuccesses)
                    .append(", \"failures\": ").append(authenticationFailures).append("},\n")
                    .append("  \"categories\": ").append(enumCountsJson(categories)).append(",\n")
                    .append("  \"levels\": ").append(enumCountsJson(levels)).append(",\n")
                    .append("  \"errorsByHour\": ").append(hourCountsJson()).append(",\n")
                    .append("  \"topSources\": [");
            List<Map.Entry<String, Long>> topSources = sources.entrySet().stream()
                    .sorted(Map.Entry.<String, Long>comparingByValue().reversed()
                            .thenComparing(Map.Entry.comparingByKey()))
                    .limit(10).toList();
            for (int i = 0; i < topSources.size(); i++) {
                Map.Entry<String, Long> source = topSources.get(i);
                if (i > 0) {
                    json.append(',');
                }
                json.append("\n    {\"source\": \"").append(jsonEscape(source.getKey()))
                        .append("\", \"count\": ").append(source.getValue()).append('}');
            }
            if (!topSources.isEmpty()) {
                json.append('\n').append("  ");
            }
            json.append("],\n  \"alerts\": [");
            for (int i = 0; i < alerts.size(); i++) {
                Alert alert = alerts.get(i);
                if (i > 0) {
                    json.append(',');
                }
                json.append("\n    {\"timestamp\": \"").append(alert.timestamp())
                        .append("\", \"type\": \"").append(jsonEscape(alert.type()))
                        .append("\", \"count\": ").append(alert.count())
                        .append(", \"source\": \"").append(jsonEscape(alert.source())).append("\"}");
            }
            if (!alerts.isEmpty()) {
                json.append('\n').append("  ");
            }
            return json.append("]\n}\n").toString();
        }

        private String enumCountsJson(Map<? extends Enum<?>, Long> counts) {
            StringBuilder json = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<? extends Enum<?>, Long> entry : counts.entrySet()) {
                if (!first) {
                    json.append(", ");
                }
                json.append('"').append(entry.getKey().name()).append("\": ").append(entry.getValue());
                first = false;
            }
            return json.append('}').toString();
        }

        private String hourCountsJson() {
            StringBuilder json = new StringBuilder("{");
            errorsByHour.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEachOrdered(entry -> {
                        if (json.length() > 1) {
                            json.append(", ");
                        }
                        json.append('"').append(String.format(Locale.ROOT, "%02d", entry.getKey()))
                                .append("\": ").append(entry.getValue());
                    });
            return json.append('}').toString();
        }

        private String jsonEscape(String value) {
            StringBuilder escaped = new StringBuilder();
            for (int i = 0; i < value.length(); i++) {
                char character = value.charAt(i);
                switch (character) {
                    case '"' -> escaped.append("\\\"");
                    case '\\' -> escaped.append("\\\\");
                    case '\b' -> escaped.append("\\b");
                    case '\f' -> escaped.append("\\f");
                    case '\n' -> escaped.append("\\n");
                    case '\r' -> escaped.append("\\r");
                    case '\t' -> escaped.append("\\t");
                    default -> {
                        if (character < 0x20) {
                            escaped.append(String.format(Locale.ROOT, "\\u%04x", (int) character));
                        } else {
                            escaped.append(character);
                        }
                    }
                }
            }
            return escaped.toString();
        }
    }

    private static final class Options {
        private Path input;
        private String format = "auto";
        private int threshold = 5;
        private int windowMinutes = 10;
        private Path jsonOutput;
        private boolean help;

        static Options parse(String[] args) {
            Options options = new Options();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "--help", "-h" -> options.help = true;
                    case "--format" -> options.format = requireValue(args, ++i, arg);
                    case "--threshold" -> options.threshold = positiveInt(requireValue(args, ++i, arg), arg);
                    case "--window-minutes" -> options.windowMinutes =
                            positiveInt(requireValue(args, ++i, arg), arg);
                    case "--json" -> options.jsonOutput = Path.of(requireValue(args, ++i, arg));
                    default -> {
                        if (arg.startsWith("--")) {
                            throw new IllegalArgumentException("Unknown option: " + arg);
                        }
                        if (options.input != null) {
                            throw new IllegalArgumentException("Only one input file can be analyzed at a time.");
                        }
                        options.input = Path.of(arg);
                    }
                }
            }
            if (options.help) {
                return options;
            }
            if (!List.of("auto", "linux", "windows-xml").contains(options.format)) {
                throw new IllegalArgumentException("Unsupported format: " + options.format);
            }
            return options;
        }

        private static String requireValue(String[] args, int index, String option) {
            if (index >= args.length || args[index].startsWith("--")) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            return args[index];
        }

        private static int positiveInt(String value, String option) {
            try {
                int parsed = Integer.parseInt(value);
                if (parsed <= 0) {
                    throw new IllegalArgumentException(option + " must be greater than zero.");
                }
                return parsed;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(option + " must be a positive integer: " + value);
            }
        }
    }
}
