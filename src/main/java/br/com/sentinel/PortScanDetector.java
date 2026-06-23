package br.com.sentinel;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PortScanDetector {

  private static final int PORT_SCAN_THRESHOLD = 20;
  private static final Duration PORT_SCAN_WINDOW = Duration.ofSeconds(60);
  private static final Duration PORT_SCAN_COOLDOWN = PORT_SCAN_WINDOW;

  private static class PortAttempt {
    private final PacketDTO packet;

    private PortAttempt(PacketDTO packet) {
      this.packet = packet;
    }
  }

  private static class SourceState {
    private final Deque<PortAttempt> attempts = new ArrayDeque<>();
    private final Map<Integer, Integer> portCounts = new HashMap<>();
    private Instant lastWarn;
    private Instant lastAlert;
  }

  private final Map<String, SourceState> stateBySource = new HashMap<>();

  public PortScanDetector(int threshold, Duration window) {
    this();
  }

  public PortScanDetector() {
  }

  public AlertEvent evaluate(PacketDTO packet) {
    if (packet == null || !"TCP".equals(packet.getProtocol())) {
      return null;
    }
    if (!packet.isTcpSyn() || packet.isTcpAck()) {
      return null;
    }
    if (packet.getSourceIp() == null || packet.getDestinationPort() == null) {
      return null;
    }

    SourceState state = stateBySource.computeIfAbsent(packet.getSourceIp(), key -> new SourceState());
    pruneOldAttempts(state, packet.getTimestamp());

    recordAttempt(state, packet);

    int uniquePorts = state.portCounts.size();
    if (uniquePorts > PORT_SCAN_THRESHOLD && shouldEmit(state.lastAlert, packet.getTimestamp())) {
      state.lastAlert = packet.getTimestamp();
      return buildAlert(
          state,
          packet,
          uniquePorts,
          AlertEvent.Severity.ALERT);
    }
    if (uniquePorts == PORT_SCAN_THRESHOLD && shouldEmit(state.lastWarn, packet.getTimestamp())) {
      state.lastWarn = packet.getTimestamp();
      return buildAlert(
          state,
          packet,
          uniquePorts,
          AlertEvent.Severity.WARN);
    }

    return null;
  }

  private AlertEvent buildAlert(
      SourceState state,
      PacketDTO packet,
      int uniquePorts,
      AlertEvent.Severity severity) {
    String description = String.format(
        "Possivel port scan: %d portas distintas em %d segundos.",
        uniquePorts,
        PORT_SCAN_WINDOW.getSeconds());
    List<PacketDTO> relatedPackets = new ArrayList<>(state.attempts.size());
    for (PortAttempt attempt : state.attempts) {
      relatedPackets.add(attempt.packet);
    }
    return new AlertEvent(
        packet.getTimestamp(),
        severity,
        AlertEvent.Type.PORT_SCAN,
        packet.getSourceIp(),
        packet.getDestinationIp(),
        description,
        relatedPackets);
  }

  private void recordAttempt(SourceState state, PacketDTO packet) {
    state.attempts.addLast(new PortAttempt(packet));
    int port = packet.getDestinationPort();
    state.portCounts.put(port, state.portCounts.getOrDefault(port, 0) + 1);
  }

  private void pruneOldAttempts(SourceState state, Instant now) {
    while (!state.attempts.isEmpty()) {
      PortAttempt attempt = state.attempts.peekFirst();
      if (Duration.between(attempt.packet.getTimestamp(), now).compareTo(PORT_SCAN_WINDOW) <= 0) {
        break;
      }
      state.attempts.removeFirst();
      int port = attempt.packet.getDestinationPort();
      int count = state.portCounts.getOrDefault(port, 0) - 1;
      if (count <= 0) {
        state.portCounts.remove(port);
      } else {
        state.portCounts.put(port, count);
      }
    }
  }

  private boolean shouldEmit(Instant lastEmission, Instant now) {
    if (lastEmission == null) {
      return true;
    }
    return Duration.between(lastEmission, now).compareTo(PORT_SCAN_COOLDOWN) > 0;
  }
}
