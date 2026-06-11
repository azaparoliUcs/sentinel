package br.com.sentinel;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class IcmpAnalyzer {

  private static final int ICMP_ECHO_REQUEST = 8;
  private static final int MAX_ICMP_PAYLOAD = 65507;

  private static final int DEFAULT_FLOOD_THRESHOLD = 100;
  private static final Duration DEFAULT_FLOOD_WINDOW = Duration.ofSeconds(5);
  private static final int DEFAULT_TUNNEL_MIN_REQUESTS = 20;
  private static final int DEFAULT_TUNNEL_SUSPICIOUS_THRESHOLD = 10;
  private static final int DEFAULT_TUNNEL_PAYLOAD_MIN = 200;
  private static final double DEFAULT_TUNNEL_ENTROPY_MIN = 7.5;
  private static final Duration DEFAULT_TUNNEL_WINDOW = Duration.ofSeconds(30);

  private static class FloodState {
    private final Deque<Instant> requests = new ArrayDeque<>();
    private Instant lastAlert;
  }

  private static class TunnelSample {
    private final Instant timestamp;
    private final boolean suspicious;

    private TunnelSample(Instant timestamp, boolean suspicious) {
      this.timestamp = timestamp;
      this.suspicious = suspicious;
    }
  }

  private static class TunnelState {
    private final Deque<TunnelSample> samples = new ArrayDeque<>();
    private int requestCount;
    private int suspiciousCount;
    private Instant lastAlert;
  }

  private final int floodThreshold;
  private final Duration floodWindow;
  private final Duration floodCooldown;
  private final int tunnelMinRequests;
  private final int tunnelSuspiciousThreshold;
  private final int tunnelPayloadMin;
  private final double tunnelEntropyMin;
  private final Duration tunnelWindow;
  private final Duration tunnelCooldown;
  private final Map<String, FloodState> floodBySource = new HashMap<>();
  private final Map<String, TunnelState> tunnelBySource = new HashMap<>();

  public IcmpAnalyzer() {
    this(
        DEFAULT_FLOOD_THRESHOLD,
        DEFAULT_FLOOD_WINDOW,
        DEFAULT_TUNNEL_MIN_REQUESTS,
        DEFAULT_TUNNEL_SUSPICIOUS_THRESHOLD,
        DEFAULT_TUNNEL_PAYLOAD_MIN,
        DEFAULT_TUNNEL_ENTROPY_MIN,
        DEFAULT_TUNNEL_WINDOW);
  }

  public IcmpAnalyzer(
      int floodThreshold,
      Duration floodWindow,
      int tunnelMinRequests,
      int tunnelSuspiciousThreshold,
      int tunnelPayloadMin,
      double tunnelEntropyMin,
      Duration tunnelWindow) {
    this.floodThreshold = floodThreshold;
    this.floodWindow = floodWindow;
    this.floodCooldown = floodWindow;
    this.tunnelMinRequests = tunnelMinRequests;
    this.tunnelSuspiciousThreshold = tunnelSuspiciousThreshold;
    this.tunnelPayloadMin = tunnelPayloadMin;
    this.tunnelEntropyMin = tunnelEntropyMin;
    this.tunnelWindow = tunnelWindow;
    this.tunnelCooldown = tunnelWindow;
  }

  public List<AlertEvent> evaluate(PacketDTO packet) {
    List<AlertEvent> alerts = new ArrayList<>();
    if (packet == null || !"ICMP".equals(packet.getProtocol())) {
      return alerts;
    }

    if (packet.getIcmpPayloadLength() != null
        && packet.getIcmpPayloadLength() > MAX_ICMP_PAYLOAD) {
      alerts.add(new AlertEvent(
          packet.getTimestamp(),
          AlertEvent.Severity.ALERT,
          AlertEvent.Type.PING_OF_DEATH,
          packet.getSourceIp(),
          packet.getDestinationIp(),
          String.format(
              "Possivel Ping of Death: payload ICMP %d bytes (limite %d).",
              packet.getIcmpPayloadLength(),
              MAX_ICMP_PAYLOAD)));
    }

    if (!isEchoRequest(packet)) {
      return alerts;
    }
    if (packet.getSourceIp() == null || packet.getTimestamp() == null) {
      return alerts;
    }

    AlertEvent floodAlert = evaluateFlood(packet);
    if (floodAlert != null) {
      alerts.add(floodAlert);
    }

    AlertEvent tunnelAlert = evaluateTunneling(packet);
    if (tunnelAlert != null) {
      alerts.add(tunnelAlert);
    }

    return alerts;
  }

  private AlertEvent evaluateFlood(PacketDTO packet) {
    FloodState state = floodBySource.computeIfAbsent(packet.getSourceIp(), key -> new FloodState());
    pruneFlood(state, packet.getTimestamp());
    state.requests.addLast(packet.getTimestamp());

    if (state.requests.size() >= floodThreshold && shouldAlert(state.lastAlert, packet.getTimestamp(), floodCooldown)) {
      state.lastAlert = packet.getTimestamp();
      String description = String.format(
          "Possivel ICMP flood: %d Echo Requests em %d segundos.",
          state.requests.size(),
          floodWindow.getSeconds());
      return new AlertEvent(
          packet.getTimestamp(),
          AlertEvent.Severity.ALERT,
          AlertEvent.Type.ICMP_FLOOD,
          packet.getSourceIp(),
          packet.getDestinationIp(),
          description);
    }
    return null;
  }

  private AlertEvent evaluateTunneling(PacketDTO packet) {
    TunnelState state = tunnelBySource.computeIfAbsent(packet.getSourceIp(), key -> new TunnelState());
    pruneTunnel(state, packet.getTimestamp());

    boolean suspicious = isSuspiciousPayload(packet);
    state.samples.addLast(new TunnelSample(packet.getTimestamp(), suspicious));
    state.requestCount++;
    if (suspicious) {
      state.suspiciousCount++;
    }

    if (state.requestCount >= tunnelMinRequests
        && state.suspiciousCount >= tunnelSuspiciousThreshold
        && shouldAlert(state.lastAlert, packet.getTimestamp(), tunnelCooldown)) {
      state.lastAlert = packet.getTimestamp();
      String description = String.format(
          "Possivel ICMP tunneling: %d de %d Echo Requests com payload >= %d bytes.",
          state.suspiciousCount,
          state.requestCount,
          tunnelPayloadMin);
      return new AlertEvent(
          packet.getTimestamp(),
          AlertEvent.Severity.ALERT,
          AlertEvent.Type.ICMP_TUNNELING,
          packet.getSourceIp(),
          packet.getDestinationIp(),
          description);
    }

    return null;
  }

  private boolean isEchoRequest(PacketDTO packet) {
    Integer type = packet.getIcmpType();
    return type != null && type == ICMP_ECHO_REQUEST;
  }

  private boolean isSuspiciousPayload(PacketDTO packet) {
    Integer length = packet.getIcmpPayloadLength();
    if (length == null || length < tunnelPayloadMin) {
      return false;
    }
    Double entropy = packet.getIcmpPayloadEntropy();
    return entropy == null || entropy >= tunnelEntropyMin;
  }

  private void pruneFlood(FloodState state, Instant now) {
    while (!state.requests.isEmpty()) {
      Instant timestamp = state.requests.peekFirst();
      if (Duration.between(timestamp, now).compareTo(floodWindow) <= 0) {
        break;
      }
      state.requests.removeFirst();
    }
  }

  private void pruneTunnel(TunnelState state, Instant now) {
    while (!state.samples.isEmpty()) {
      TunnelSample sample = state.samples.peekFirst();
      if (Duration.between(sample.timestamp, now).compareTo(tunnelWindow) <= 0) {
        break;
      }
      state.samples.removeFirst();
      state.requestCount = Math.max(0, state.requestCount - 1);
      if (sample.suspicious) {
        state.suspiciousCount = Math.max(0, state.suspiciousCount - 1);
      }
    }
  }

  private boolean shouldAlert(Instant lastAlert, Instant now, Duration cooldown) {
    if (lastAlert == null) {
      return true;
    }
    return Duration.between(lastAlert, now).compareTo(cooldown) > 0;
  }
}
