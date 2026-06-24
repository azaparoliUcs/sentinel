package br.com.sentinel.analysis;

import br.com.sentinel.model.AlertEvent;
import java.time.Duration;
import java.util.List;
import lombok.experimental.UtilityClass;

@UtilityClass
public final class PortScanAlertMerger {

  public static int findReplaceableWarnIndex(
      List<AlertEvent> alerts,
      AlertEvent current,
      int windowSeconds) {
    if (alerts == null || current == null) {
      return -1;
    }
    for (int i = alerts.size() - 1; i >= 0; i--) {
      AlertEvent previous = alerts.get(i);
      if (!isSamePortScanIncident(previous, current, windowSeconds)) {
        continue;
      }
      if (previous.getSeverity() != AlertEvent.Severity.WARN) {
        continue;
      }
      return i;
    }
    return -1;
  }

  public static boolean isSamePortScanIncident(
      AlertEvent previous,
      AlertEvent current,
      int windowSeconds) {
    if (previous == null || current == null) {
      return false;
    }
    if (previous.getType() != AlertEvent.Type.PORT_SCAN
        || current.getType() != AlertEvent.Type.PORT_SCAN) {
      return false;
    }
    if (previous.getSourceIp() == null || current.getSourceIp() == null) {
      return false;
    }
    if (previous.getDestinationIp() == null || current.getDestinationIp() == null) {
      return false;
    }
    if (!previous.getSourceIp().equals(current.getSourceIp())) {
      return false;
    }
    if (!previous.getDestinationIp().equals(current.getDestinationIp())) {
      return false;
    }
    return Duration.between(previous.getTimestamp(), current.getTimestamp())
        .compareTo(Duration.ofSeconds(windowSeconds)) <= 0;
  }
}
