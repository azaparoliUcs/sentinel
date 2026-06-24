package br.com.sentinel.format;

import br.com.sentinel.model.AlertEvent;
import lombok.experimental.UtilityClass;
import java.time.format.DateTimeFormatter;

@UtilityClass
public final class AlertFormatter {

  public static String formatConsoleLine(AlertEvent alert) {
    if (alert == null) {
      return "-";
    }
    String time = DateTimeFormatter.ISO_INSTANT.format(alert.getTimestamp());
    return String.format(
        "%s | %s | %s | %s -> %s | %s",
        time,
        alert.getSeverity(),
        alert.getType(),
        alert.getSourceIp() == null ? "-" : alert.getSourceIp(),
        alert.getDestinationIp() == null ? "-" : alert.getDestinationIp(),
        alert.getDescription());
  }

  public static String buildAlertSummary(AlertEvent alert) {
    if (alert == null) {
      return "";
    }
    StringBuilder details = new StringBuilder();
    details.append("Linha gerada:\n");
    details.append(formatConsoleLine(alert)).append("\n\n");
    details.append("Descrição do alerta:\n");
    details.append(PacketFormatter.nullSafe(alert.getDescription())).append("\n\n");
    details.append("Como o alerta foi gerado:\n");
    details.append(explainAlert(alert.getType()));
    details.append("\n\nPortas tentadas:\n");
    details.append(PacketFormatter.formatPortSummary(alert.getRelatedPackets()));
    return details.toString();
  }

  public static String explainAlert(AlertEvent.Type type) {
    if (type == null) {
      return "Sem detalhes adicionais disponíveis.";
    }

    return switch (type) {
      case PORT_SCAN -> "O detector acompanha conexões TCP com SYN sem ACK da mesma origem. "
          + "Quando o total de portas distintas dentro da janela configurada atinge o limite, "
          + "o alerta é emitido.";
      case FRAGMENTATION -> "O analisador monitora fragmentos IPv4 do mesmo ID, origem e destino. "
          + "Ele gera o alerta quando encontra fragmentos sobrepostos ou fragmentos muito pequenos.";
      default -> "Sem detalhes adicionais disponíveis.";
    };
  }
}
