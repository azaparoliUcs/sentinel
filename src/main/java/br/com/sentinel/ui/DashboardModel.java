package br.com.sentinel.ui;

import br.com.sentinel.analysis.DetectionConfig;
import br.com.sentinel.analysis.PortScanAlertMerger;
import br.com.sentinel.model.AlertEvent;
import br.com.sentinel.model.PacketDTO;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import lombok.Getter;

@Getter
public final class DashboardModel {

  private final ObservableList<AlertEvent> alerts = FXCollections.observableArrayList();
  private final ObservableList<PacketDTO> packets = FXCollections.observableArrayList();

  private int packetCount;
  private int infoCount;
  private int warnCount;
  private int alertCount;
  private int portScanCount;
  private int fragmentationCount;

  public void clear() {
    alerts.clear();
    packets.clear();
    packetCount = 0;
    infoCount = 0;
    warnCount = 0;
    alertCount = 0;
    portScanCount = 0;
    fragmentationCount = 0;
  }

  public void addPacket(PacketDTO packet) {
    if (packet == null) {
      return;
    }
    packets.add(packet);
    packetCount++;
  }

  public void addAlert(AlertEvent alert) {
    if (alert == null) {
      return;
    }
    if (alert.getType() == AlertEvent.Type.PORT_SCAN
        && alert.getSeverity() == AlertEvent.Severity.ALERT
        && replacePendingPortScanWarn(alert)) {
      alertCount++;
      return;
    }

    alerts.add(alert);
    incrementCounts(alert);
  }

  private void incrementCounts(AlertEvent alert) {
    switch (alert.getSeverity()) {
      case INFO -> infoCount++;
      case WARN -> warnCount++;
      case ALERT -> alertCount++;
      default -> {
      }
    }
    switch (alert.getType()) {
      case PORT_SCAN -> portScanCount++;
      case FRAGMENTATION -> fragmentationCount++;
      default -> {
      }
    }
  }

  private boolean replacePendingPortScanWarn(AlertEvent alert) {
    int index = PortScanAlertMerger.findReplaceableWarnIndex(
        alerts,
        alert,
        DetectionConfig.PORT_SCAN_WINDOW_SECONDS);
    if (index < 0) {
      return false;
    }
    alerts.remove(index);
    warnCount--;
    alerts.add(index, alert);
    return true;
  }
}
