package br.com.sentinel.analysis;

import br.com.sentinel.model.AlertEvent;
import br.com.sentinel.model.PacketDTO;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class FragmentationAnalyzer {

  private static class FragmentKey {
    private final String sourceIp;
    private final String destinationIp;
    private final Integer identification;
    private final String protocol;

    private FragmentKey(String sourceIp, String destinationIp, Integer identification, String protocol) {
      this.sourceIp = sourceIp;
      this.destinationIp = destinationIp;
      this.identification = identification;
      this.protocol = protocol;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof FragmentKey)) {
        return false;
      }
      FragmentKey that = (FragmentKey) o;
      return Objects.equals(sourceIp, that.sourceIp)
          && Objects.equals(destinationIp, that.destinationIp)
          && Objects.equals(identification, that.identification)
          && Objects.equals(protocol, that.protocol);
    }

    @Override
    public int hashCode() {
      return Objects.hash(sourceIp, destinationIp, identification, protocol);
    }
  }

  private static class FragmentRange {
    private final int start;
    private final int end;

    private FragmentRange(int start, int end) {
      this.start = start;
      this.end = end;
    }
  }

  private static class FragmentState {
    private final List<FragmentRange> ranges = new ArrayList<>();
    private Instant lastSeen;
    private boolean overlapAlerted;
    private boolean tinyAlerted;
  }

  private final int minFragmentSize;
  private final Duration retention = Duration.ofMinutes(2);
  private final Map<FragmentKey, FragmentState> fragments = new HashMap<>();

  public FragmentationAnalyzer(int minFragmentSize) {
    this.minFragmentSize = minFragmentSize;
  }

  public AlertEvent evaluate(PacketDTO packet) {
    if (packet == null || !packet.isIpv4Fragmented()) {
      return null;
    }
    if (packet.getSourceIp() == null
        || packet.getDestinationIp() == null
        || packet.getIpv4Identification() == null
        || packet.getIpv4FragmentOffset() == null
        || packet.getIpv4PayloadLength() == null) {
      return null;
    }

    cleanupOld(packet.getTimestamp());

    FragmentKey key = new FragmentKey(
        packet.getSourceIp(),
        packet.getDestinationIp(),
        packet.getIpv4Identification(),
        packet.getProtocol());
    FragmentState state = fragments.computeIfAbsent(key, k -> new FragmentState());
    state.lastSeen = packet.getTimestamp();

    int start = packet.getIpv4FragmentOffset();
    int end = start + Math.max(0, packet.getIpv4PayloadLength() - 1);
    FragmentRange range = new FragmentRange(start, end);

    boolean overlapDetected = detectOverlap(state, range);
    boolean tinyFragmentDetected = packet.getIpv4PayloadLength() < minFragmentSize;

    state.ranges.add(range);

    if (overlapDetected && !state.overlapAlerted) {
      state.overlapAlerted = true;
      String description = String.format(
          "Fragmentos IPv4 sobrepostos (ID %d) entre %s e %s.",
          packet.getIpv4Identification(),
          packet.getSourceIp(),
          packet.getDestinationIp());
      return new AlertEvent(
          packet.getTimestamp(),
          AlertEvent.Severity.ALERT,
          AlertEvent.Type.FRAGMENTATION,
          packet.getSourceIp(),
          packet.getDestinationIp(),
          description);
    }

    if (tinyFragmentDetected && !state.tinyAlerted) {
      state.tinyAlerted = true;
      String description = String.format(
          "Fragmento IPv4 pequeno detectado (tamanho %d bytes, ID %d).",
          packet.getIpv4PayloadLength(),
          packet.getIpv4Identification());
      return new AlertEvent(
          packet.getTimestamp(),
          AlertEvent.Severity.WARN,
          AlertEvent.Type.FRAGMENTATION,
          packet.getSourceIp(),
          packet.getDestinationIp(),
          description);
    }

    return null;
  }

  private boolean detectOverlap(FragmentState state, FragmentRange candidate) {
    for (FragmentRange existing : state.ranges) {
      if (candidate.start <= existing.end && candidate.end >= existing.start) {
        return true;
      }
    }
    return false;
  }

  private void cleanupOld(Instant now) {
    List<FragmentKey> toRemove = new ArrayList<>();
    for (Map.Entry<FragmentKey, FragmentState> entry : fragments.entrySet()) {
      if (Duration.between(entry.getValue().lastSeen, now).compareTo(retention) > 0) {
        toRemove.add(entry.getKey());
      }
    }
    for (FragmentKey key : toRemove) {
      fragments.remove(key);
    }
  }
}
