package br.com.sentinel;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class AlertEvent {

  public enum Severity {
    INFO,
    WARN,
    ALERT
  }

  public enum Type {
    PORT_SCAN,
    FRAGMENTATION
  }

  private final Instant timestamp;
  private final Severity severity;
  private final Type type;
  private final String sourceIp;
  private final String destinationIp;
  private final String description;
  private final List<PacketDTO> relatedPackets;

  public AlertEvent(
      Instant timestamp,
      Severity severity,
      Type type,
      String sourceIp,
      String destinationIp,
      String description) {
    this(timestamp, severity, type, sourceIp, destinationIp, description, List.of());
  }

  public AlertEvent(
      Instant timestamp,
      Severity severity,
      Type type,
      String sourceIp,
      String destinationIp,
      String description,
      List<PacketDTO> relatedPackets) {
    this.timestamp = timestamp;
    this.severity = severity;
    this.type = type;
    this.sourceIp = sourceIp;
    this.destinationIp = destinationIp;
    this.description = description;
    this.relatedPackets = relatedPackets == null ? List.of() : List.copyOf(relatedPackets);
  }

  public Instant getTimestamp() {
    return timestamp;
  }

  public Severity getSeverity() {
    return severity;
  }

  public Type getType() {
    return type;
  }

  public String getSourceIp() {
    return sourceIp;
  }

  public String getDestinationIp() {
    return destinationIp;
  }

  public String getDescription() {
    return description;
  }

  public List<PacketDTO> getRelatedPackets() {
    return relatedPackets;
  }

  public String toConsoleLine() {
    String time = DateTimeFormatter.ISO_INSTANT.format(timestamp);
    return String.format(
        "%s | %s | %s | %s -> %s | %s",
        time,
        severity,
        type,
        sourceIp == null ? "-" : sourceIp,
        destinationIp == null ? "-" : destinationIp,
        description);
  }

  public String toCsvRow() {
    return String.format(
        "%s,%s,%s,%s,%s,%s",
        DateTimeFormatter.ISO_INSTANT.format(timestamp),
        severity,
        type,
        escapeCsv(sourceIp),
        escapeCsv(destinationIp),
        escapeCsv(description));
  }

  private String escapeCsv(String value) {
    if (value == null) {
      return "";
    }
    String escaped = value.replace("\"", "\"\"");
    return "\"" + escaped + "\"";
  }
}
