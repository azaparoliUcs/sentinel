package br.com.sentinel.model;

import java.time.Instant;
import java.util.List;
import lombok.Builder;
import lombok.Value;

@Value
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

  @Builder
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
}
