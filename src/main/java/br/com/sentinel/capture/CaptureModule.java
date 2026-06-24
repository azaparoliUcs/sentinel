package br.com.sentinel.capture;

import br.com.sentinel.analysis.SecurityAnalyzer;
import br.com.sentinel.model.AlertEvent;
import br.com.sentinel.model.PacketDTO;
import br.com.sentinel.output.OutputDispatcher;
import br.com.sentinel.parse.PacketParser;
import java.io.EOFException;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

public class CaptureModule {

  private static final int SNAPLEN = 65536;
  private static final int READ_TIMEOUT = 10;

  private final String interfaceName;
  private final String filePath;
  private final PacketParser parser;
  private final SecurityAnalyzer analyzer;
  private final OutputDispatcher outputDispatcher;

  private volatile boolean running = true;
  private PcapHandle handle;

  public CaptureModule(
      String interfaceName,
      String filePath,
      PacketParser parser,
      SecurityAnalyzer analyzer,
      OutputDispatcher outputDispatcher) {
    this.interfaceName = interfaceName;
    this.filePath = filePath;
    this.parser = parser;
    this.analyzer = analyzer;
    this.outputDispatcher = outputDispatcher;
  }

  public void start() throws IOException, NotOpenException, PcapNativeException {
    handle = openHandle();

    try {
      while (running) {
        Packet packet;
        try {
          packet = handle.getNextPacketEx();
        } catch (EOFException eof) {
          break;
        } catch (TimeoutException timeout) {
          continue;
        }

        Instant timestamp = handle.getTimestamp().toInstant();
        PacketDTO dto = parser.parse(packet, timestamp);
        if (dto == null) {
          continue;
        }

        outputDispatcher.printPacket(dto);
        List<AlertEvent> alerts = analyzer.analyze(dto);
        for (AlertEvent alert : alerts) {
          outputDispatcher.writeAlert(alert);
        }
      }
    } finally {
      closeHandle();
    }
  }

  public void stop() {
    running = false;
    closeHandle();
  }

  private PcapHandle openHandle() throws IOException, PcapNativeException {
    if (filePath != null) {
      return Pcaps.openOffline(filePath);
    }

    PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
    if (nif == null) {
      throw new IllegalArgumentException("Interface nao encontrada: " + interfaceName);
    }
    return nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
  }

  private void closeHandle() {
    if (handle != null && handle.isOpen()) {
      handle.close();
    }
  }
}
