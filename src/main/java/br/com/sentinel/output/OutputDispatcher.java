package br.com.sentinel.output;

import java.io.Closeable;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

import br.com.sentinel.format.AlertFormatter;
import br.com.sentinel.model.AlertEvent;
import br.com.sentinel.model.PacketDTO;

public class OutputDispatcher implements Closeable {

  private final PrintWriter alertWriter;
  private final Consumer<AlertEvent> alertListener;
  private final Consumer<PacketDTO> packetListener;

  public OutputDispatcher(Path logPath, Consumer<AlertEvent> alertListener, Consumer<PacketDTO> packetListener)
      throws IOException {
    if (logPath != null) {
      this.alertWriter = new PrintWriter(Files.newBufferedWriter(logPath, StandardCharsets.UTF_8));
    } else {
      this.alertWriter = null;
    }
    this.alertListener = alertListener;
    this.packetListener = packetListener;
  }

  public void printPacket(PacketDTO packet) {
    if (packet == null) {
      return;
    }
    String time = DateTimeFormatter.ISO_INSTANT.format(packet.getTimestamp());
    String source = packet.getSourceIp() == null ? "-" : packet.getSourceIp();
    String destination = packet.getDestinationIp() == null ? "-" : packet.getDestinationIp();
    String protocol = packet.getProtocol() == null ? "-" : packet.getProtocol();
    System.out.println(String.format("%s | %s | %s -> %s", time, protocol, source, destination));
    if (packetListener != null) {
      packetListener.accept(packet);
    }
  }

  public void writeAlert(AlertEvent alert) {
    if (alert == null) {
      return;
    }
    boolean shouldPersist = !(alert.getType() == AlertEvent.Type.PORT_SCAN
        && alert.getSeverity() == AlertEvent.Severity.WARN);

    if (shouldPersist) {
      String line = AlertFormatter.formatConsoleLine(alert);
      System.out.println(line);
      if (alertWriter != null) {
        alertWriter.println(line);
        alertWriter.flush();
      }
    }
    if (alertListener != null) {
      alertListener.accept(alert);
    }
  }

  @Override
  public void close() throws IOException {
    if (alertWriter != null) {
      alertWriter.flush();
      alertWriter.close();
    }
  }
}
