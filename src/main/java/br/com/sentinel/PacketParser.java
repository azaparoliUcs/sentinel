package br.com.sentinel;

import java.time.Instant;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class PacketParser {

  public PacketDTO parse(Packet packet, Instant timestamp) {
    if (packet == null || timestamp == null) {
      return null;
    }

    PacketDTO.Builder builder = PacketDTO.builder().timestamp(timestamp);

    if (packet.contains(IpV4Packet.class)) {
      IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
      IpV4Packet.IpV4Header header = ipV4Packet.getHeader();
      builder
          .sourceIp(header.getSrcAddr().getHostAddress())
          .destinationIp(header.getDstAddr().getHostAddress())
          .protocol(header.getProtocol().name())
          .ipv4Identification(header.getIdentificationAsInt())
          .ipv4FragmentOffset(header.getFragmentOffset() * 8)
          .ipv4MoreFragments(header.getMoreFragmentFlag())
          .ipv4PayloadLength(Math.max(0, header.getTotalLengthAsInt() - header.getIhl() * 4));
    }

    if (packet.contains(TcpPacket.class)) {
      TcpPacket tcpPacket = packet.get(TcpPacket.class);
      TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
      builder
          .protocol("TCP")
          .sourcePort(tcpHeader.getSrcPort().valueAsInt())
          .destinationPort(tcpHeader.getDstPort().valueAsInt())
          .tcpSyn(tcpHeader.getSyn())
          .tcpAck(tcpHeader.getAck())
          .tcpRst(tcpHeader.getRst())
          .tcpFin(tcpHeader.getFin());
    } else if (packet.contains(UdpPacket.class)) {
      UdpPacket udpPacket = packet.get(UdpPacket.class);
      UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
      builder
          .protocol("UDP")
          .sourcePort(udpHeader.getSrcPort().valueAsInt())
          .destinationPort(udpHeader.getDstPort().valueAsInt());
    } else if (packet.contains(IcmpV4CommonPacket.class)) {
      IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
      IcmpV4CommonPacket.IcmpV4CommonHeader icmpHeader = icmpPacket.getHeader();
      builder
          .protocol("ICMP")
          .icmpType(toUnsignedInt(icmpHeader.getType().value()))
          .icmpCode(toUnsignedInt(icmpHeader.getCode().value()));

      byte[] payload = null;
      if (packet.contains(IcmpV4EchoPacket.class)) {
        IcmpV4EchoPacket echoPacket = packet.get(IcmpV4EchoPacket.class);
        IcmpV4EchoPacket.IcmpV4EchoHeader echoHeader = echoPacket.getHeader();
        builder
            .icmpIdentifier(toUnsignedInt(echoHeader.getIdentifier()))
            .icmpSequence(toUnsignedInt(echoHeader.getSequenceNumber()));
        if (echoPacket.getPayload() != null) {
          payload = echoPacket.getPayload().getRawData();
        }
      }

      if (payload == null && icmpPacket.getPayload() != null) {
        payload = icmpPacket.getPayload().getRawData();
      }

      if (payload != null) {
        builder
            .icmpPayloadLength(payload.length)
            .icmpPayloadEntropy(calculateEntropy(payload));
      }
    }

    return builder.build();
  }

  private int toUnsignedInt(byte value) {
    return value & 0xFF;
  }

  private int toUnsignedInt(short value) {
    return value & 0xFFFF;
  }

  private Double calculateEntropy(byte[] data) {
    if (data == null || data.length == 0) {
      return null;
    }
    int[] counts = new int[256];
    for (byte b : data) {
      counts[b & 0xFF]++;
    }
    double entropy = 0.0;
    for (int count : counts) {
      if (count == 0) {
        continue;
      }
      double p = (double) count / data.length;
      entropy -= p * (Math.log(p) / Math.log(2));
    }
    return entropy;
  }
}
