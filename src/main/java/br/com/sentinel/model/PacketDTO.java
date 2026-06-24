package br.com.sentinel.model;

import java.time.Instant;
import lombok.Builder;
import lombok.Value;

@Value
@Builder(toBuilder = true)
public class PacketDTO {

  private final Instant timestamp;
  private final String sourceIp;
  private final String destinationIp;
  private final Integer sourcePort;
  private final Integer destinationPort;
  private final String protocol;
  private final boolean tcpSyn;
  private final boolean tcpAck;
  private final boolean tcpRst;
  private final boolean tcpFin;
  private final Integer ipv4Identification;
  private final Integer ipv4FragmentOffset;
  private final boolean ipv4MoreFragments;
  private final Integer ipv4PayloadLength;

  public boolean isIpv4Fragmented() {
    return ipv4FragmentOffset != null
        && (ipv4FragmentOffset > 0 || ipv4MoreFragments);
  }
}
