package br.com.sentinel;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public class Main {

  private static final int DEFAULT_PORT_SCAN_THRESHOLD = 10;
  private static final int DEFAULT_PORT_SCAN_WINDOW_SECONDS = 10;
  private static final int DEFAULT_FRAGMENT_MIN_SIZE = 400;

  public static void main(String[] args) {
    Config config;
    try {
      config = parseArgs(args);
    } catch (IllegalArgumentException ex) {
      System.err.println("Erro: " + ex.getMessage());
      printUsage();
      return;
    }

    if (config == null) {
      printUsage();
      return;
    }

    try (OutputModule outputModule = new OutputModule(config.logPath, config.reportPath)) {
      PacketParser parser = new PacketParser();
      PortScanDetector portScanDetector = new PortScanDetector(
          config.portScanThreshold,
          Duration.ofSeconds(config.portScanWindowSeconds));
      FragmentationAnalyzer fragmentationAnalyzer = new FragmentationAnalyzer(config.fragmentMinSize);
      SecurityAnalyzer analyzer = new SecurityAnalyzer(
          portScanDetector,
          fragmentationAnalyzer,
          new IcmpAnalyzer());
      CaptureModule captureModule = new CaptureModule(
          config.interfaceName,
          config.filePath,
          config.filter,
          parser,
          analyzer,
          outputModule);

      Runtime.getRuntime().addShutdownHook(new Thread(captureModule::stop));

      captureModule.start();
    } catch (IOException | NotOpenException | PcapNativeException ex) {
      System.err.println("Falha ao iniciar captura: " + ex.getMessage());
    }
  }

  private static Config parseArgs(String[] args) {
    if (args == null || args.length == 0) {
      return null;
    }

    Config config = new Config();
    config.portScanThreshold = DEFAULT_PORT_SCAN_THRESHOLD;
    config.portScanWindowSeconds = DEFAULT_PORT_SCAN_WINDOW_SECONDS;
    config.fragmentMinSize = DEFAULT_FRAGMENT_MIN_SIZE;
    config.logPath = Paths.get("alerts.log");
    config.reportPath = Paths.get("report.csv");

    for (int i = 0; i < args.length; i++) {
      String arg = args[i];
      switch (arg) {
        case "--interface":
          config.interfaceName = nextValue(args, ++i, arg);
          break;
        case "--file":
          config.filePath = nextValue(args, ++i, arg);
          break;
        case "--filter":
          config.filter = nextValue(args, ++i, arg);
          break;
        case "--port-scan-threshold":
          config.portScanThreshold = Integer.parseInt(nextValue(args, ++i, arg));
          break;
        case "--port-scan-window":
          config.portScanWindowSeconds = Integer.parseInt(nextValue(args, ++i, arg));
          break;
        case "--fragment-min-size":
          config.fragmentMinSize = Integer.parseInt(nextValue(args, ++i, arg));
          break;
        case "--log":
          config.logPath = Paths.get(nextValue(args, ++i, arg));
          break;
        case "--report":
          config.reportPath = Paths.get(nextValue(args, ++i, arg));
          break;
        case "--help":
          return null;
        default:
          throw new IllegalArgumentException("Parametro desconhecido: " + arg);
      }
    }

    if ((config.interfaceName == null && config.filePath == null)
        || (config.interfaceName != null && config.filePath != null)) {
      throw new IllegalArgumentException("Informe --interface ou --file (apenas um).");
    }

    return config;
  }

  private static String nextValue(String[] args, int index, String option) {
    if (index >= args.length) {
      throw new IllegalArgumentException("Valor ausente para " + option);
    }
    return args[index];
  }

  private static void printUsage() {
    System.out.println("Uso:");
    System.out.println("  java -jar analyzer.jar --interface <iface> [opcoes]");
    System.out.println("  java -jar analyzer.jar --file <arquivo.pcap> [opcoes]");
    System.out.println();
    System.out.println("Opcoes:");
    System.out.println("  --filter <bpf>               Filtro BPF opcional.");
    System.out.println("  --port-scan-threshold <n>    Numero de portas distintas para alerta.");
    System.out.println("  --port-scan-window <seg>     Janela de tempo em segundos.");
    System.out.println("  --fragment-min-size <bytes>  Tamanho minimo de fragmento IPv4.");
    System.out.println("  --log <arquivo>              Caminho para log de alertas.");
    System.out.println("  --report <arquivo>           Caminho para relatorio CSV.");
    System.out.println("  --help                       Exibe esta ajuda.");
  }

  private static class Config {
    private String interfaceName;
    private String filePath;
    private String filter;
    private int portScanThreshold;
    private int portScanWindowSeconds;
    private int fragmentMinSize;
    private Path logPath;
    private Path reportPath;
  }
}
