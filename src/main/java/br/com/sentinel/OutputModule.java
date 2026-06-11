package br.com.sentinel;

import java.io.Closeable;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

public class OutputModule implements Closeable {

  private final PrintWriter alertWriter;
  private final PrintWriter reportWriter;
  private final boolean logEnabled;
  private final boolean reportEnabled;
  private final Consumer<AlertEvent> alertListener;
  private final Consumer<PacketDTO> packetListener;

  public OutputModule(Path logPath, Path reportPath) throws IOException {
    this(logPath, reportPath, null, null);
  }

  public OutputModule(Path logPath, Path reportPath, Consumer<AlertEvent> alertListener)
      throws IOException {
    this(logPath, reportPath, alertListener, null);
  }

  public OutputModule(
      Path logPath,
      Path reportPath,
      Consumer<AlertEvent> alertListener,
      Consumer<PacketDTO> packetListener) throws IOException {
    if (logPath != null) {
      alertWriter = new PrintWriter(Files.newBufferedWriter(logPath, StandardCharsets.UTF_8));
      logEnabled = true;
    } else {
      alertWriter = null;
      logEnabled = false;
    }

    if (reportPath != null) {
      reportWriter = new PrintWriter(Files.newBufferedWriter(reportPath, StandardCharsets.UTF_8));
      reportWriter.println("timestamp,severity,type,source_ip,destination_ip,description");
      reportEnabled = true;
    } else {
      reportWriter = null;
      reportEnabled = false;
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
    String summary = String.format(
        "%s | %s | %s -> %s",
        time,
        protocol,
        source,
        destination);
    System.out.println(summary);
    notifyPacketListener(packet);
  }

  public void writeAlert(AlertEvent alert) {
    if (alert == null) {
      return;
    }
    System.out.println(alert.toConsoleLine());
    if (logEnabled) {
      alertWriter.println(alert.toConsoleLine());
      alertWriter.flush();
    }
    if (reportEnabled) {
      reportWriter.println(alert.toCsvRow());
      reportWriter.flush();
    }
    notifyListener(alert);
  }

  private void notifyListener(AlertEvent alert) {
    if (alertListener == null || alert == null) {
      return;
    }
    try {
      alertListener.accept(alert);
    } catch (RuntimeException ex) {
      System.err.println("Falha ao notificar listener de alerta: " + ex.getMessage());
    }
  }

  private void notifyPacketListener(PacketDTO packet) {
    if (packetListener == null || packet == null) {
      return;
    }
    try {
      packetListener.accept(packet);
    } catch (RuntimeException ex) {
      System.err.println("Falha ao notificar listener de pacote: " + ex.getMessage());
    }
  }

  @Override
  public void close() throws IOException {
    if (alertWriter != null) {
      alertWriter.flush();
      alertWriter.close();
    }
    if (reportWriter != null) {
      reportWriter.flush();
      reportWriter.close();
    }
  }
}
