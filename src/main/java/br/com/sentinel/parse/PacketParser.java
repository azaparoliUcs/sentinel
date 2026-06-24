package br.com.sentinel.parse;

import br.com.sentinel.model.PacketDTO;
import java.time.Instant;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class PacketParser {

  public PacketDTO parse(Packet packet, Instant timestamp) {
    if (packet == null || timestamp == null) {
      return null;
    }

    var builder = PacketDTO.builder().timestamp(timestamp);

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
    }

    return builder.build();
  }
}
