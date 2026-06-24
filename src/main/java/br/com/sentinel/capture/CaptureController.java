package br.com.sentinel.capture;

import br.com.sentinel.analysis.FragmentationAnalyzer;
import br.com.sentinel.analysis.PortScanDetector;
import br.com.sentinel.analysis.SecurityAnalyzer;
import br.com.sentinel.model.AlertEvent;
import br.com.sentinel.model.PacketDTO;
import br.com.sentinel.output.OutputDispatcher;
import br.com.sentinel.parse.PacketParser;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public final class CaptureController {

  private final ExecutorService executor = Executors.newSingleThreadExecutor();
  private Future<?> captureFuture;
  private CaptureModule captureModule;

  public boolean isRunning() {
    return captureFuture != null && !captureFuture.isDone();
  }

  public void startCapture(
      String interfaceName,
      String filePath,
      int fragmentMinSize,
      Consumer<AlertEvent> alertConsumer,
      Consumer<PacketDTO> packetConsumer,
      Consumer<String> errorConsumer,
      Runnable onFinished) {
    if (isRunning()) {
      if (errorConsumer != null) {
        errorConsumer.accept("Uma captura já está em execução.");
      }
      return;
    }

    captureFuture = executor.submit(() -> {
      try (OutputDispatcher outputDispatcher = createOutputDispatcher(alertConsumer, packetConsumer)) {
        captureModule = new CaptureModule(
            interfaceName,
            filePath,
            new PacketParser(),
            new SecurityAnalyzer(
                new PortScanDetector(),
                new FragmentationAnalyzer(fragmentMinSize)),
            outputDispatcher);
        captureModule.start();
      } catch (IOException | NotOpenException | PcapNativeException | RuntimeException ex) {
        if (errorConsumer != null) {
          errorConsumer.accept("Falha na captura: " + ex.getMessage());
        }
      } finally {
        captureModule = null;
        if (onFinished != null) {
          onFinished.run();
        }
      }
    });
  }

  public void stopCapture() {
    if (captureModule != null) {
      captureModule.stop();
    }
  }

  public void shutdown() {
    stopCapture();
    executor.shutdownNow();
  }

  private OutputDispatcher createOutputDispatcher(
      Consumer<AlertEvent> alertConsumer,
      Consumer<PacketDTO> packetConsumer) throws IOException {
    Path logPath = Paths.get("alerts.log");
    return new OutputDispatcher(logPath, alertConsumer, packetConsumer);
  }
}
