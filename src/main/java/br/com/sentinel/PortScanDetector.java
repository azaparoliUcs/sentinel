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

  private static class PortAttempt {
    private final PacketDTO packet;

    private PortAttempt(PacketDTO packet) {
      this.packet = packet;
    }
  }

  private static class SourceState {
    private final Deque<PortAttempt> attempts = new ArrayDeque<>();
    private final Map<Integer, Integer> portCounts = new HashMap<>();
    private Instant lastAlert;
  }

  private final int threshold;
  private final Duration window;
  private final Duration alertCooldown;
  private final Map<String, SourceState> stateBySource = new HashMap<>();

  public PortScanDetector(int threshold, Duration window) {
    this.threshold = threshold;
    this.window = window;
    this.alertCooldown = window;
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
    if (uniquePorts >= threshold && shouldAlert(state, packet.getTimestamp())) {
      state.lastAlert = packet.getTimestamp();
      String description = String.format(
          "Possivel port scan: %d portas distintas em %d segundos.",
          uniquePorts,
          window.getSeconds());
      List<PacketDTO> relatedPackets = new ArrayList<>(state.attempts.size());
      for (PortAttempt attempt : state.attempts) {
        relatedPackets.add(attempt.packet);
      }
      return new AlertEvent(
          packet.getTimestamp(),
          AlertEvent.Severity.ALERT,
          AlertEvent.Type.PORT_SCAN,
          packet.getSourceIp(),
          packet.getDestinationIp(),
          description,
          relatedPackets);
    }

    return null;
  }

  private void recordAttempt(SourceState state, PacketDTO packet) {
    state.attempts.addLast(new PortAttempt(packet));
    int port = packet.getDestinationPort();
    state.portCounts.put(port, state.portCounts.getOrDefault(port, 0) + 1);
  }

  private void pruneOldAttempts(SourceState state, Instant now) {
    while (!state.attempts.isEmpty()) {
      PortAttempt attempt = state.attempts.peekFirst();
      if (Duration.between(attempt.packet.getTimestamp(), now).compareTo(window) <= 0) {
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

  private boolean shouldAlert(SourceState state, Instant now) {
    if (state.lastAlert == null) {
      return true;
    }
    return Duration.between(state.lastAlert, now).compareTo(alertCooldown) > 0;
  }
}
