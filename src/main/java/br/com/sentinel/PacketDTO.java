package br.com.sentinel;

import java.time.Instant;

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
  private final Integer icmpType;
  private final Integer icmpCode;
  private final Integer icmpIdentifier;
  private final Integer icmpSequence;
  private final Integer icmpPayloadLength;
  private final Double icmpPayloadEntropy;

  private PacketDTO(Builder builder) {
    this.timestamp = builder.timestamp;
    this.sourceIp = builder.sourceIp;
    this.destinationIp = builder.destinationIp;
    this.sourcePort = builder.sourcePort;
    this.destinationPort = builder.destinationPort;
    this.protocol = builder.protocol;
    this.tcpSyn = builder.tcpSyn;
    this.tcpAck = builder.tcpAck;
    this.tcpRst = builder.tcpRst;
    this.tcpFin = builder.tcpFin;
    this.ipv4Identification = builder.ipv4Identification;
    this.ipv4FragmentOffset = builder.ipv4FragmentOffset;
    this.ipv4MoreFragments = builder.ipv4MoreFragments;
    this.ipv4PayloadLength = builder.ipv4PayloadLength;
    this.icmpType = builder.icmpType;
    this.icmpCode = builder.icmpCode;
    this.icmpIdentifier = builder.icmpIdentifier;
    this.icmpSequence = builder.icmpSequence;
    this.icmpPayloadLength = builder.icmpPayloadLength;
    this.icmpPayloadEntropy = builder.icmpPayloadEntropy;
  }

  public Instant getTimestamp() {
    return timestamp;
  }

  public String getSourceIp() {
    return sourceIp;
  }

  public String getDestinationIp() {
    return destinationIp;
  }

  public Integer getSourcePort() {
    return sourcePort;
  }

  public Integer getDestinationPort() {
    return destinationPort;
  }

  public String getProtocol() {
    return protocol;
  }

  public boolean isTcpSyn() {
    return tcpSyn;
  }

  public boolean isTcpAck() {
    return tcpAck;
  }

  public boolean isTcpRst() {
    return tcpRst;
  }

  public boolean isTcpFin() {
    return tcpFin;
  }

  public Integer getIpv4Identification() {
    return ipv4Identification;
  }

  public Integer getIpv4FragmentOffset() {
    return ipv4FragmentOffset;
  }

  public boolean isIpv4MoreFragments() {
    return ipv4MoreFragments;
  }

  public Integer getIpv4PayloadLength() {
    return ipv4PayloadLength;
  }

  public Integer getIcmpType() {
    return icmpType;
  }

  public Integer getIcmpCode() {
    return icmpCode;
  }

  public Integer getIcmpIdentifier() {
    return icmpIdentifier;
  }

  public Integer getIcmpSequence() {
    return icmpSequence;
  }

  public Integer getIcmpPayloadLength() {
    return icmpPayloadLength;
  }

  public Double getIcmpPayloadEntropy() {
    return icmpPayloadEntropy;
  }

  public boolean isIpv4Fragmented() {
    return ipv4FragmentOffset != null
        && (ipv4FragmentOffset > 0 || ipv4MoreFragments);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private Instant timestamp;
    private String sourceIp;
    private String destinationIp;
    private Integer sourcePort;
    private Integer destinationPort;
    private String protocol;
    private boolean tcpSyn;
    private boolean tcpAck;
    private boolean tcpRst;
    private boolean tcpFin;
    private Integer ipv4Identification;
    private Integer ipv4FragmentOffset;
    private boolean ipv4MoreFragments;
    private Integer ipv4PayloadLength;
    private Integer icmpType;
    private Integer icmpCode;
    private Integer icmpIdentifier;
    private Integer icmpSequence;
    private Integer icmpPayloadLength;
    private Double icmpPayloadEntropy;

    public Builder timestamp(Instant timestamp) {
      this.timestamp = timestamp;
      return this;
    }

    public Builder sourceIp(String sourceIp) {
      this.sourceIp = sourceIp;
      return this;
    }

    public Builder destinationIp(String destinationIp) {
      this.destinationIp = destinationIp;
      return this;
    }

    public Builder sourcePort(Integer sourcePort) {
      this.sourcePort = sourcePort;
      return this;
    }

    public Builder destinationPort(Integer destinationPort) {
      this.destinationPort = destinationPort;
      return this;
    }

    public Builder protocol(String protocol) {
      this.protocol = protocol;
      return this;
    }

    public Builder tcpSyn(boolean tcpSyn) {
      this.tcpSyn = tcpSyn;
      return this;
    }

    public Builder tcpAck(boolean tcpAck) {
      this.tcpAck = tcpAck;
      return this;
    }

    public Builder tcpRst(boolean tcpRst) {
      this.tcpRst = tcpRst;
      return this;
    }

    public Builder tcpFin(boolean tcpFin) {
      this.tcpFin = tcpFin;
      return this;
    }

    public Builder ipv4Identification(Integer ipv4Identification) {
      this.ipv4Identification = ipv4Identification;
      return this;
    }

    public Builder ipv4FragmentOffset(Integer ipv4FragmentOffset) {
      this.ipv4FragmentOffset = ipv4FragmentOffset;
      return this;
    }

    public Builder ipv4MoreFragments(boolean ipv4MoreFragments) {
      this.ipv4MoreFragments = ipv4MoreFragments;
      return this;
    }

    public Builder ipv4PayloadLength(Integer ipv4PayloadLength) {
      this.ipv4PayloadLength = ipv4PayloadLength;
      return this;
    }

    public Builder icmpType(Integer icmpType) {
      this.icmpType = icmpType;
      return this;
    }

    public Builder icmpCode(Integer icmpCode) {
      this.icmpCode = icmpCode;
      return this;
    }

    public Builder icmpIdentifier(Integer icmpIdentifier) {
      this.icmpIdentifier = icmpIdentifier;
      return this;
    }

    public Builder icmpSequence(Integer icmpSequence) {
      this.icmpSequence = icmpSequence;
      return this;
    }

    public Builder icmpPayloadLength(Integer icmpPayloadLength) {
      this.icmpPayloadLength = icmpPayloadLength;
      return this;
    }

    public Builder icmpPayloadEntropy(Double icmpPayloadEntropy) {
      this.icmpPayloadEntropy = icmpPayloadEntropy;
      return this;
    }

    public PacketDTO build() {
      return new PacketDTO(this);
    }
  }
}
