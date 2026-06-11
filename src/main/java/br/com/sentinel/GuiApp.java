package br.com.sentinel;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Spinner;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public class GuiApp extends Application {

  private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ISO_INSTANT;
  private static final int DEFAULT_PORT_SCAN_THRESHOLD = 10;
  private static final int DEFAULT_PORT_SCAN_WINDOW_SECONDS = 10;
  private static final int DEFAULT_FRAGMENT_MIN_SIZE = 400;

  private final ObservableList<AlertEvent> alerts = FXCollections.observableArrayList();
  private final ObservableList<PacketDTO> packets = FXCollections.observableArrayList();
  private final ExecutorService executor = Executors.newSingleThreadExecutor();
  private final AtomicBoolean stopRequested = new AtomicBoolean(false);

  private CaptureModule captureModule;
  private Future<?> captureFuture;
  private Stage primaryStage;

  private Label statusLabel;
  private Label totalLabel;
  private Label infoLabel;
  private Label warnLabel;
  private Label alertLabel;
  private Label portScanLabel;
  private Label fragmentationLabel;
  private Label icmpFloodLabel;
  private Label pingOfDeathLabel;
  private Label icmpTunnelLabel;

  private int packetCount;
  private int infoCount;
  private int warnCount;
  private int alertCount;
  private int portScanCount;
  private int fragmentationCount;
  private int icmpFloodCount;
  private int pingOfDeathCount;
  private int icmpTunnelCount;

  private Button startButton;
  private Button stopButton;

  public static void main(String[] args) {
    launch(args);
  }

  @Override
  public void start(Stage stage) {
    primaryStage = stage;

    RadioButton fileRadio = new RadioButton("Arquivo PCAP");
    RadioButton interfaceRadio = new RadioButton("Interface");
    ToggleGroup sourceGroup = new ToggleGroup();
    fileRadio.setToggleGroup(sourceGroup);
    interfaceRadio.setToggleGroup(sourceGroup);
    fileRadio.setSelected(true);

    TextField fileField = new TextField();
    fileField.setPromptText("Selecione um arquivo .pcap");
    Button browseButton = new Button("Procurar...");
    browseButton.setOnAction(event -> chooseFile(stage, fileField));

    TextField interfaceField = new TextField();
    interfaceField.setPromptText("Ex: eth0");

    TextField filterField = new TextField();
    filterField.setPromptText("Ex: tcp and port 80");

    Spinner<Integer> thresholdSpinner = new Spinner<>(1, 1000, DEFAULT_PORT_SCAN_THRESHOLD);
    thresholdSpinner.setEditable(true);
    Spinner<Integer> windowSpinner = new Spinner<>(1, 3600, DEFAULT_PORT_SCAN_WINDOW_SECONDS);
    windowSpinner.setEditable(true);
    Spinner<Integer> fragmentSpinner = new Spinner<>(1, 65535, DEFAULT_FRAGMENT_MIN_SIZE);
    fragmentSpinner.setEditable(true);

    startButton = new Button("Iniciar");
    stopButton = new Button("Parar");
    stopButton.setDisable(true);
    Button clearButton = new Button("Limpar");

    startButton.setOnAction(event -> {
      String filePath = fileRadio.isSelected() ? fileField.getText().trim() : null;
      String interfaceName = interfaceRadio.isSelected() ? interfaceField.getText().trim() : null;
      String filter = filterField.getText().trim();
      if (!validateInputs(fileRadio.isSelected(), filePath, interfaceName)) {
        return;
      }
      startCapture(
          interfaceName,
          filePath,
          filter.isEmpty() ? null : filter,
          thresholdSpinner.getValue(),
          windowSpinner.getValue(),
          fragmentSpinner.getValue());
    });

    stopButton.setOnAction(event -> stopCapture());
    clearButton.setOnAction(event -> clearAlerts());

    fileRadio.selectedProperty().addListener((obs, oldVal, newVal) -> {
      fileField.setDisable(!newVal);
      browseButton.setDisable(!newVal);
      interfaceField.setDisable(newVal);
    });
    fileField.setDisable(false);
    browseButton.setDisable(false);
    interfaceField.setDisable(true);

    GridPane form = new GridPane();
    form.setHgap(10);
    form.setVgap(8);
    form.add(new Label("Fonte:"), 0, 0);
    form.add(new HBox(10, fileRadio, interfaceRadio), 1, 0);
    form.add(new Label("Arquivo:"), 0, 1);
    form.add(buildFileBox(fileField, browseButton), 1, 1);
    form.add(new Label("Interface:"), 0, 2);
    form.add(interfaceField, 1, 2);
    form.add(new Label("Filtro BPF:"), 0, 3);
    form.add(filterField, 1, 3);
    form.add(new Label("Port scan (qtd):"), 0, 4);
    form.add(thresholdSpinner, 1, 4);
    form.add(new Label("Janela (seg):"), 0, 5);
    form.add(windowSpinner, 1, 5);
    form.add(new Label("Fragmento mín (bytes):"), 0, 6);
    form.add(fragmentSpinner, 1, 6);

    HBox actions = new HBox(10, startButton, stopButton, clearButton);
    actions.setPadding(new Insets(10, 0, 0, 0));

    VBox topBox = new VBox(10, form, actions);
    topBox.setPadding(new Insets(12));

    TableView<AlertEvent> alertTable = buildAlertTable();
    TableView<PacketDTO> packetTable = buildPacketTable();
    TabPane tabPane = new TabPane();
    Tab alertTab = new Tab("Alertas", alertTable);
    Tab packetTab = new Tab("Pacotes", packetTable);
    alertTab.setClosable(false);
    packetTab.setClosable(false);
    tabPane.getTabs().addAll(alertTab, packetTab);

    statusLabel = new Label("Status: parado");
    totalLabel = new Label("Pacotes: 0");
    infoLabel = new Label("Info: 0");
    warnLabel = new Label("Warn: 0");
    alertLabel = new Label("Alert: 0");
    portScanLabel = new Label("Port scan: 0");
    fragmentationLabel = new Label("Fragmentação: 0");
    icmpFloodLabel = new Label("ICMP flood: 0");
    pingOfDeathLabel = new Label("Ping of Death: 0");
    icmpTunnelLabel = new Label("ICMP tunneling: 0");

    HBox statsBar = new HBox(
        16,
        statusLabel,
        totalLabel,
        infoLabel,
        warnLabel,
        alertLabel,
        portScanLabel,
        fragmentationLabel,
        icmpFloodLabel,
        pingOfDeathLabel,
        icmpTunnelLabel);
    statsBar.setPadding(new Insets(10, 12, 12, 12));

    BorderPane root = new BorderPane();
    root.setTop(topBox);
    root.setCenter(tabPane);
    root.setBottom(statsBar);

    Scene scene = new Scene(root, 1100, 650);
    stage.setTitle("Pcap4J Security Analyzer");
    stage.setScene(scene);
    stage.show();
  }

  @Override
  public void stop() {
    stopCapture();
    executor.shutdownNow();
  }

  private void chooseFile(Stage stage, TextField fileField) {
    FileChooser chooser = new FileChooser();
    chooser.setTitle("Selecionar arquivo PCAP");
    chooser.getExtensionFilters().add(
        new FileChooser.ExtensionFilter("PCAP", "*.pcap", "*.pcapng"));
    if (fileField.getText() != null && !fileField.getText().trim().isEmpty()) {
      java.io.File current = new java.io.File(fileField.getText().trim());
      if (current.getParentFile() != null && current.getParentFile().exists()) {
        chooser.setInitialDirectory(current.getParentFile());
      }
      chooser.setInitialFileName(current.getName());
    }
    java.io.File file = chooser.showOpenDialog(stage);
    if (file != null) {
      fileField.setText(file.getAbsolutePath());
    }
  }

  private HBox buildFileBox(TextField fileField, Button browseButton) {
    HBox box = new HBox(8, fileField, browseButton);
    HBox.setHgrow(fileField, Priority.ALWAYS);
    return box;
  }

  private TableView<AlertEvent> buildAlertTable() {
    TableView<AlertEvent> table = new TableView<>(alerts);
    table.setPlaceholder(new Label("Nenhum alerta gerado ainda."));
    table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);

    TableColumn<AlertEvent, String> timeColumn = new TableColumn<>("Timestamp");
    timeColumn.setCellValueFactory(data -> new ReadOnlyStringWrapper(
        TIMESTAMP_FORMATTER.format(data.getValue().getTimestamp())));

    TableColumn<AlertEvent, String> severityColumn = new TableColumn<>("Severidade");
    severityColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(data.getValue().getSeverity().name()));

    TableColumn<AlertEvent, String> typeColumn = new TableColumn<>("Tipo");
    typeColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(data.getValue().getType().name()));

    TableColumn<AlertEvent, String> sourceColumn = new TableColumn<>("Origem");
    sourceColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(nullSafe(data.getValue().getSourceIp())));

    TableColumn<AlertEvent, String> destinationColumn = new TableColumn<>("Destino");
    destinationColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(nullSafe(data.getValue().getDestinationIp())));

    TableColumn<AlertEvent, String> descriptionColumn = new TableColumn<>("Descricao");
    descriptionColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(data.getValue().getDescription()));

    descriptionColumn.setMinWidth(300);
    TableColumn<AlertEvent, Void> actionColumn = buildAlertActionColumn(table);

    table.getColumns().add(timeColumn);
    table.getColumns().add(severityColumn);
    table.getColumns().add(typeColumn);
    table.getColumns().add(sourceColumn);
    table.getColumns().add(destinationColumn);
    table.getColumns().add(descriptionColumn);
    table.getColumns().add(actionColumn);

    return table;
  }

  private TableColumn<AlertEvent, Void> buildAlertActionColumn(TableView<AlertEvent> table) {
    TableColumn<AlertEvent, Void> actionColumn = new TableColumn<>("Ações");
    actionColumn.setMinWidth(110);
    actionColumn.setMaxWidth(110);
    actionColumn.setResizable(false);
    actionColumn.setCellFactory(col -> new TableCell<>() {
      private final Button detailsButton = new Button("Detalhes");

      {
        detailsButton.setOnAction(event -> {
          AlertEvent alert = getTableRow() == null ? null : getTableRow().getItem();
          if (alert == null) {
            return;
          }
          int index = table.getItems().indexOf(alert);
          if (index >= 0) {
            table.getSelectionModel().select(index);
            table.scrollTo(index);
          }
          openAlertDetailsWindow(alert);
        });
      }

      @Override
      protected void updateItem(Void item, boolean empty) {
        super.updateItem(item, empty);
        setText(null);
        setGraphic(empty ? null : detailsButton);
      }
    });
    return actionColumn;
  }

  private TableView<PacketDTO> buildPacketTable() {
    TableView<PacketDTO> table = new TableView<>(packets);
    table.setPlaceholder(new Label("Nenhum pacote capturado ainda."));
    table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);

    TableColumn<PacketDTO, String> timeColumn = new TableColumn<>("Timestamp");
    timeColumn.setCellValueFactory(data -> new ReadOnlyStringWrapper(
        TIMESTAMP_FORMATTER.format(data.getValue().getTimestamp())));

    TableColumn<PacketDTO, String> protocolColumn = new TableColumn<>("Protocolo");
    protocolColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(nullSafe(data.getValue().getProtocol())));

    TableColumn<PacketDTO, String> sourceColumn = new TableColumn<>("Origem");
    sourceColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(formatEndpoint(data.getValue().getSourceIp(),
            data.getValue().getSourcePort())));

    TableColumn<PacketDTO, String> destinationColumn = new TableColumn<>("Destino");
    destinationColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(formatEndpoint(data.getValue().getDestinationIp(),
            data.getValue().getDestinationPort())));

    TableColumn<PacketDTO, String> descriptionColumn = new TableColumn<>("Descricao");
    descriptionColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(describePacket(data.getValue())));

    descriptionColumn.setMinWidth(320);
    table.getColumns().add(timeColumn);
    table.getColumns().add(protocolColumn);
    table.getColumns().add(sourceColumn);
    table.getColumns().add(destinationColumn);
    table.getColumns().add(descriptionColumn);

    return table;
  }

  private boolean validateInputs(boolean fileMode, String filePath, String interfaceName) {
    if (captureFuture != null && !captureFuture.isDone()) {
      showError("Uma captura já está em execução.");
      return false;
    }
    if (fileMode && (filePath == null || filePath.isEmpty())) {
      showError("Informe um arquivo PCAP para iniciar.");
      return false;
    }
    if (!fileMode && (interfaceName == null || interfaceName.isEmpty())) {
      showError("Informe uma interface de rede para iniciar.");
      return false;
    }
    return true;
  }

  private void startCapture(
      String interfaceName,
      String filePath,
      String filter,
      int portScanThreshold,
      int portScanWindowSeconds,
      int fragmentMinSize) {
    stopRequested.set(false);
    updateRunningState(true);

    captureFuture = executor.submit(() -> {
      try (OutputModule outputModule = createOutputModule()) {
        captureModule = new CaptureModule(
            interfaceName,
            filePath,
            filter,
            new PacketParser(),
            new SecurityAnalyzer(
                new PortScanDetector(portScanThreshold, Duration.ofSeconds(portScanWindowSeconds)),
                new FragmentationAnalyzer(fragmentMinSize),
                new IcmpAnalyzer()),
            outputModule);
        captureModule.start();
      } catch (IOException | NotOpenException | PcapNativeException | RuntimeException ex) {
        if (!stopRequested.get()) {
          Platform.runLater(() -> showError("Falha ao iniciar captura: " + ex.getMessage()));
        }
      } finally {
        Platform.runLater(() -> updateRunningState(false));
      }
    });
  }

  private OutputModule createOutputModule() {
    Path logPath = Paths.get("alerts.log");
    Path reportPath = Paths.get("report.csv");
    try {
      return new OutputModule(
          logPath,
          reportPath,
          alert -> Platform.runLater(() -> addAlert(alert)),
          packet -> Platform.runLater(() -> addPacket(packet)));
    } catch (IOException ex) {
      throw new IllegalStateException("Falha ao criar arquivos de saída: " + ex.getMessage(), ex);
    }
  }

  private void stopCapture() {
    stopRequested.set(true);
    if (captureModule != null) {
      captureModule.stop();
    }
    updateRunningState(false);
  }

  private void clearAlerts() {
    alerts.clear();
    packets.clear();
    packetCount = 0;
    infoCount = 0;
    warnCount = 0;
    alertCount = 0;
    portScanCount = 0;
    fragmentationCount = 0;
    icmpFloodCount = 0;
    pingOfDeathCount = 0;
    icmpTunnelCount = 0;
    refreshStats();
  }

  private void addAlert(AlertEvent alert) {
    if (alert == null) {
      return;
    }
    alerts.add(alert);
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
      case ICMP_FLOOD -> icmpFloodCount++;
      case PING_OF_DEATH -> pingOfDeathCount++;
      case ICMP_TUNNELING -> icmpTunnelCount++;
      default -> {
      }
    }
    refreshStats();
  }

  private void addPacket(PacketDTO packet) {
    if (packet == null) {
      return;
    }
    packets.add(packet);
    packetCount++;
    refreshStats();
  }

  private void refreshStats() {
    totalLabel.setText("Pacotes: " + packetCount);
    infoLabel.setText("Info: " + infoCount);
    warnLabel.setText("Warn: " + warnCount);
    alertLabel.setText("Alert: " + alertCount);
    portScanLabel.setText("Port scan: " + portScanCount);
    fragmentationLabel.setText("Fragmentação: " + fragmentationCount);
    icmpFloodLabel.setText("ICMP flood: " + icmpFloodCount);
    pingOfDeathLabel.setText("Ping of Death: " + pingOfDeathCount);
    icmpTunnelLabel.setText("ICMP tunneling: " + icmpTunnelCount);
  }

  private void updateRunningState(boolean running) {
    if (statusLabel != null) {
      statusLabel.setText("Status: " + (running ? "rodando" : "parado"));
    }
    if (startButton != null) {
      startButton.setDisable(running);
    }
    if (stopButton != null) {
      stopButton.setDisable(!running);
    }
  }

  private void showError(String message) {
    Alert alert = new Alert(Alert.AlertType.ERROR);
    alert.setTitle("Erro");
    alert.setHeaderText("Falha na execução");
    alert.setContentText(message);
    alert.showAndWait();
  }

  private void openAlertDetailsWindow(AlertEvent alert) {
    if (alert == null) {
      return;
    }

    Stage detailStage = new Stage();
    if (primaryStage != null) {
      detailStage.initOwner(primaryStage);
    }
    detailStage.initModality(Modality.NONE);
    detailStage.setTitle("Detalhamento - " + alert.getType().name());

    TextArea summaryArea = new TextArea(buildAlertSummary(alert));
    summaryArea.setEditable(false);
    summaryArea.setWrapText(true);
    summaryArea.setFocusTraversable(false);
    summaryArea.setPrefRowCount(8);

    TableView<PacketDTO> relatedPacketTable = buildRelatedPacketTable(alert.getRelatedPackets());

    Label summaryLabel = new Label("Resumo");
    Label packetLabel = new Label("Pacotes relacionados");
    Button closeButton = new Button("Fechar");
    closeButton.setOnAction(event -> detailStage.close());

    HBox footer = new HBox(closeButton);
    footer.setAlignment(Pos.CENTER_RIGHT);

    VBox content = new VBox(10, summaryLabel, summaryArea, packetLabel, relatedPacketTable, footer);
    content.setPadding(new Insets(12));
    VBox.setVgrow(relatedPacketTable, Priority.ALWAYS);

    Scene scene = new Scene(content, 1100, 750);
    detailStage.setScene(scene);
    detailStage.show();
    detailStage.toFront();
  }

  private String buildAlertSummary(AlertEvent alert) {
    List<PacketDTO> relatedPackets = alert.getRelatedPackets();
    StringBuilder details = new StringBuilder();
    details.append("Linha gerada:\n");
    details.append(alert.toConsoleLine()).append("\n\n");
    details.append("Descrição do alerta:\n");
    details.append(nullSafe(alert.getDescription())).append("\n\n");
    details.append("Como o alerta foi gerado:\n");
    details.append(explainAlert(alert.getType()));
    details.append("\n\nPortas tentadas:\n");
    details.append(formatPortSummary(relatedPackets));
    return details.toString();
  }

  private String explainAlert(AlertEvent.Type type) {
    if (type == null) {
      return "Sem detalhes adicionais disponíveis.";
    }

    return switch (type) {
      case PORT_SCAN -> "O detector acompanha conexões TCP com SYN sem ACK da mesma origem. "
          + "Quando o total de portas distintas dentro da janela configurada atinge o limite, "
          + "o alerta é emitido.";
      case FRAGMENTATION -> "O analisador monitora fragmentos IPv4 do mesmo ID, origem e destino. "
          + "Ele gera o alerta quando encontra fragmentos sobrepostos ou fragmentos muito pequenos.";
      case ICMP_FLOOD -> "O analisador conta Echo Requests ICMP por origem dentro de uma janela curta. "
          + "Ao ultrapassar o limite configurado, ele dispara o alerta.";
      case PING_OF_DEATH -> "O alerta é gerado quando o payload ICMP ultrapassa o limite máximo esperado, "
          + "indicando possível ataque Ping of Death.";
      case ICMP_TUNNELING -> "O detector acompanha Echo Requests com payload grande e entropia suspeita. "
          + "Quando há volume e padrão suficiente na janela analisada, o alerta é gerado.";
      default -> "Sem detalhes adicionais disponíveis.";
    };
  }

  private String describePacket(PacketDTO packet) {
    if (packet == null) {
      return "-";
    }
    String protocol = nullSafe(packet.getProtocol());
    StringBuilder description = new StringBuilder(protocol);
    if ("TCP".equals(protocol)) {
      String flags = buildTcpFlags(packet);
      if (!flags.isEmpty()) {
        description.append(" flags=").append(flags);
      }
    } else if ("ICMP".equals(protocol)) {
      if (packet.getIcmpType() != null) {
        description.append(" type=").append(packet.getIcmpType());
      }
      if (packet.getIcmpCode() != null) {
        description.append(" code=").append(packet.getIcmpCode());
      }
      if (packet.getIcmpPayloadLength() != null) {
        description.append(" len=").append(packet.getIcmpPayloadLength());
      }
      if (packet.getIcmpIdentifier() != null) {
        description.append(" id=").append(packet.getIcmpIdentifier());
      }
      if (packet.getIcmpSequence() != null) {
        description.append(" seq=").append(packet.getIcmpSequence());
      }
    }
    if (packet.isIpv4Fragmented()) {
      description.append(" | fragmento offset=")
          .append(nullSafeInteger(packet.getIpv4FragmentOffset()));
      if (packet.getIpv4PayloadLength() != null) {
        description.append(" len=").append(packet.getIpv4PayloadLength());
      }
      description.append(packet.isIpv4MoreFragments() ? " MF" : " LF");
    }
    return description.toString();
  }

  private String formatPortSummary(List<PacketDTO> packets) {
    Map<Integer, Integer> portCounts = new LinkedHashMap<>();
    for (PacketDTO packet : packets) {
      if (packet == null || packet.getDestinationPort() == null) {
        continue;
      }
      int port = packet.getDestinationPort();
      portCounts.put(port, portCounts.getOrDefault(port, 0) + 1);
    }

    if (portCounts.isEmpty()) {
      return "Nenhuma porta de destino registrada.";
    }

    StringBuilder summary = new StringBuilder();
    for (Map.Entry<Integer, Integer> entry : portCounts.entrySet()) {
      summary.append("- Porta ")
          .append(entry.getKey())
          .append(" (")
          .append(entry.getValue())
          .append(entry.getValue() == 1 ? " pacote)" : " pacotes)")
          .append("\n");
    }
    return summary.toString().trim();
  }

  private String buildTcpFlags(PacketDTO packet) {
    List<String> flags = new ArrayList<>();
    if (packet.isTcpSyn()) {
      flags.add("SYN");
    }
    if (packet.isTcpAck()) {
      flags.add("ACK");
    }
    if (packet.isTcpFin()) {
      flags.add("FIN");
    }
    if (packet.isTcpRst()) {
      flags.add("RST");
    }
    return String.join(",", flags);
  }

  private String formatEndpoint(String ip, Integer port) {
    if (ip == null || ip.trim().isEmpty()) {
      return "-";
    }
    if (port == null) {
      return ip;
    }
    return ip + ":" + port;
  }

  private String nullSafeInteger(Integer value) {
    return value == null ? "-" : value.toString();
  }

  private String nullSafe(String value) {
    return value == null ? "-" : value;
  }

  private TableView<PacketDTO> buildRelatedPacketTable(List<PacketDTO> relatedPackets) {
    TableView<PacketDTO> table = new TableView<>(FXCollections.observableArrayList(relatedPackets));
    table.setPlaceholder(new Label("Nenhum pacote relacionado foi armazenado para este alerta."));
    table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);

    TableColumn<PacketDTO, String> timeColumn = new TableColumn<>("Timestamp");
    timeColumn.setCellValueFactory(data -> new ReadOnlyStringWrapper(
        TIMESTAMP_FORMATTER.format(data.getValue().getTimestamp())));

    TableColumn<PacketDTO, String> sourceColumn = new TableColumn<>("Origem");
    sourceColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(formatEndpoint(data.getValue().getSourceIp(),
            data.getValue().getSourcePort())));

    TableColumn<PacketDTO, String> destinationColumn = new TableColumn<>("Destino");
    destinationColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(formatEndpoint(data.getValue().getDestinationIp(),
            data.getValue().getDestinationPort())));

    TableColumn<PacketDTO, String> destinationPortColumn = new TableColumn<>("Porta destino");
    destinationPortColumn.setMinWidth(110);
    destinationPortColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(nullSafeInteger(data.getValue().getDestinationPort())));

    TableColumn<PacketDTO, String> descriptionColumn = new TableColumn<>("Descricao");
    descriptionColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(describePacket(data.getValue())));
    descriptionColumn.setMinWidth(250);

    table.getColumns().add(timeColumn);
    table.getColumns().add(sourceColumn);
    table.getColumns().add(destinationColumn);
    table.getColumns().add(destinationPortColumn);
    table.getColumns().add(descriptionColumn);
    return table;
  }
}
