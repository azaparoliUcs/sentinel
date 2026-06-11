package br.com.sentinel;

import java.util.ArrayList;
import java.util.List;

public class SecurityAnalyzer {

  private final PortScanDetector portScanDetector;
  private final FragmentationAnalyzer fragmentationAnalyzer;
  private final IcmpAnalyzer icmpAnalyzer;

  public SecurityAnalyzer(PortScanDetector portScanDetector,
                          FragmentationAnalyzer fragmentationAnalyzer,
                          IcmpAnalyzer icmpAnalyzer) {
    this.portScanDetector = portScanDetector;
    this.fragmentationAnalyzer = fragmentationAnalyzer;
    this.icmpAnalyzer = icmpAnalyzer;
  }

  public List<AlertEvent> analyze(PacketDTO packet) {
    List<AlertEvent> alerts = new ArrayList<>();
    if (packet == null) {
      return alerts;
    }

    AlertEvent portScanAlert = portScanDetector.evaluate(packet);
    if (portScanAlert != null) {
      alerts.add(portScanAlert);
    }

    AlertEvent fragmentationAlert = fragmentationAnalyzer.evaluate(packet);
    if (fragmentationAlert != null) {
      alerts.add(fragmentationAlert);
    }

    if (icmpAnalyzer != null) {
      alerts.addAll(icmpAnalyzer.evaluate(packet));
    }

    return alerts;
  }
}
