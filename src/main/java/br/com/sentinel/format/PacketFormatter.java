package br.com.sentinel.format;

import br.com.sentinel.model.PacketDTO;
import lombok.experimental.UtilityClass;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@UtilityClass
public final class PacketFormatter {

  public static String describePacket(PacketDTO packet) {
    if (packet == null) {
      return "-";
    }
    String protocol = nullSafe(packet.getProtocol());
    StringBuilder description = new StringBuilder(protocol);
    if ("TCP".equals(protocol)) {
      String flags = buildTcpFlags(packet);
      if (!flags.isEmpty()) {
        description.append(" flags=").append(flags);
      }
    }
    if (packet.isIpv4Fragmented()) {
      description.append(" | fragmento offset=")
          .append(nullSafeInteger(packet.getIpv4FragmentOffset()));
      if (packet.getIpv4PayloadLength() != null) {
        description.append(" len=").append(packet.getIpv4PayloadLength());
      }
      description.append(packet.isIpv4MoreFragments() ? " MF" : " LF");
    }
    return description.toString();
  }

  public static String formatPortSummary(List<PacketDTO> packets) {
    Map<Integer, Integer> portCounts = new LinkedHashMap<>();
    for (PacketDTO packet : packets) {
      if (packet == null || packet.getDestinationPort() == null) {
        continue;
      }
      int port = packet.getDestinationPort();
      portCounts.put(port, portCounts.getOrDefault(port, 0) + 1);
    }

    if (portCounts.isEmpty()) {
      return "Nenhuma porta de destino registrada.";
    }

    StringBuilder summary = new StringBuilder();
    for (Map.Entry<Integer, Integer> entry : portCounts.entrySet()) {
      summary.append("- Porta ")
          .append(entry.getKey())
          .append(" (")
          .append(entry.getValue())
          .append(entry.getValue() == 1 ? " pacote)" : " pacotes)")
          .append("\n");
    }
    return summary.toString().trim();
  }

  public static String formatEndpoint(String ip, Integer port) {
    if (ip == null || ip.trim().isEmpty()) {
      return "-";
    }
    if (port == null) {
      return ip;
    }
    return ip + ":" + port;
  }

  public static String formatFragmentationSummary(List<PacketDTO> packets) {
    if (packets == null || packets.isEmpty()) {
      return "Nenhum fragmento relacionado armazenado.";
    }

    StringBuilder summary = new StringBuilder();
    PacketDTO first = null;
    int index = 1;
    for (PacketDTO packet : packets) {
      if (packet == null || !packet.isIpv4Fragmented()) {
        continue;
      }
      if (first == null) {
        first = packet;
      }
      summary.append("- Fragmento ")
          .append(index++)
          .append(": offset=")
          .append(nullSafeInteger(packet.getIpv4FragmentOffset()))
          .append(", payload=")
          .append(nullSafeInteger(packet.getIpv4PayloadLength()))
          .append(" bytes, ")
          .append(packet.isIpv4MoreFragments() ? "MF" : "LF")
          .append("\n");
    }

    if (first != null) {
      summary.insert(0, String.format(
          "Datagrama IPv4: %s -> %s | ID=%s | protocolo=%s%n",
          nullSafe(first.getSourceIp()),
          nullSafe(first.getDestinationIp()),
          nullSafeInteger(first.getIpv4Identification()),
          nullSafe(first.getProtocol())));
    }

    if (summary.length() == 0) {
      return "Nenhum fragmento relacionado armazenado.";
    }

    return summary.toString().trim();
  }

  public static String buildTcpFlags(PacketDTO packet) {
    List<String> flags = new ArrayList<>();
    if (packet.isTcpSyn()) {
      flags.add("SYN");
    }
    if (packet.isTcpAck()) {
      flags.add("ACK");
    }
    if (packet.isTcpFin()) {
      flags.add("FIN");
    }
    if (packet.isTcpRst()) {
      flags.add("RST");
    }
    return String.join(",", flags);
  }

  public static String nullSafeInteger(Integer value) {
    return value == null ? "-" : value.toString();
  }

  public static String nullSafe(String value) {
    return value == null ? "-" : value;
  }
}
