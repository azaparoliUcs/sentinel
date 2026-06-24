package br.com.sentinel.analysis;

import br.com.sentinel.model.AlertEvent;
import br.com.sentinel.model.PacketDTO;
import java.util.ArrayList;
import java.util.List;

public class SecurityAnalyzer {

  private final PortScanDetector portScanDetector;
  private final FragmentationAnalyzer fragmentationAnalyzer;

  public SecurityAnalyzer(PortScanDetector portScanDetector,
                          FragmentationAnalyzer fragmentationAnalyzer) {
    this.portScanDetector = portScanDetector;
    this.fragmentationAnalyzer = fragmentationAnalyzer;
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

    return alerts;
  }
}
