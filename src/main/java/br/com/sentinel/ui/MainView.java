package br.com.sentinel.ui;

import java.io.File;
import java.util.List;
import java.util.function.Consumer;

import br.com.sentinel.analysis.DetectionConfig;
import br.com.sentinel.capture.CaptureRequest;
import br.com.sentinel.capture.NetworkInterfaceProvider;
import br.com.sentinel.model.AlertEvent;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Spinner;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import lombok.Getter;

public final class MainView {

  @Getter
  private final BorderPane root;
  private final Label statusLabel;
  private final Label totalLabel;
  private final Label infoLabel;
  private final Label warnLabel;
  private final Label alertLabel;
  private final Label portScanLabel;
  private final Label fragmentationLabel;
  private final Button startButton;
  private final Button stopButton;

  private MainView(
      BorderPane root,
      Label statusLabel,
      Label totalLabel,
      Label infoLabel,
      Label warnLabel,
      Label alertLabel,
      Label portScanLabel,
      Label fragmentationLabel,
      Button startButton,
      Button stopButton) {
    this.root = root;
    this.statusLabel = statusLabel;
    this.totalLabel = totalLabel;
    this.infoLabel = infoLabel;
    this.warnLabel = warnLabel;
    this.alertLabel = alertLabel;
    this.portScanLabel = portScanLabel;
    this.fragmentationLabel = fragmentationLabel;
    this.startButton = startButton;
    this.stopButton = stopButton;
  }

  public static MainView create(
      Stage owner,
      DashboardModel model,
      Consumer<CaptureRequest> onStart,
      Runnable onStop,
      Runnable onClear,
      Consumer<AlertEvent> onDetails,
      Consumer<String> onError) {
    RadioButton fileRadio = new RadioButton("Arquivo PCAP");
    RadioButton interfaceRadio = new RadioButton("Interface");
    ToggleGroup sourceGroup = new ToggleGroup();
    fileRadio.setToggleGroup(sourceGroup);
    interfaceRadio.setToggleGroup(sourceGroup);
    fileRadio.setSelected(true);

    TextField fileField = new TextField();
    fileField.setPromptText("Selecione um arquivo .pcap");
    Button browseButton = new Button("Procurar...");

    ComboBox<String> interfaceComboBox = new ComboBox<>();
    interfaceComboBox.setPrefWidth(360);

    Spinner<Integer> fragmentSpinner = new Spinner<>(1, 65535, DetectionConfig.DEFAULT_FRAGMENT_MIN_SIZE);
    fragmentSpinner.setEditable(true);

    Label portScanThresholdLabel = new Label(DetectionConfig.PORT_SCAN_THRESHOLD + " portas fixas");
    Label portScanWindowLabel = new Label(DetectionConfig.PORT_SCAN_WINDOW_SECONDS + " segundos fixos");

    Button startButton = new Button("Iniciar");
    Button stopButton = new Button("Parar");
    stopButton.setDisable(true);
    Button clearButton = new Button("Limpar");

    Label statusLabel = new Label("Status: parado");
    Label totalLabel = new Label("Pacotes: 0");
    Label infoLabel = new Label("Info: 0");
    Label warnLabel = new Label("Warn: 0");
    Label alertLabel = new Label("Alert: 0");
    Label portScanLabel = new Label("Port scan: 0");
    Label fragmentationLabel = new Label("Fragmentação: 0");

    fileField.setDisable(false);
    browseButton.setDisable(false);
    interfaceComboBox.setDisable(true);

    browseButton.setOnAction(event -> chooseFile(owner, fileField));

    startButton.setOnAction(event -> {
      CaptureRequest request = buildRequest(
          fileRadio.isSelected(),
          interfaceRadio.isSelected(),
          fileField.getText(),
          interfaceComboBox.getValue(),
          fragmentSpinner.getValue());
      if (request == null) {
        onError.accept("Informe a fonte correta antes de iniciar.");
        return;
      }
      onStart.accept(request);
    });

    stopButton.setOnAction(event -> onStop.run());
    clearButton.setOnAction(event -> onClear.run());

    fileRadio.selectedProperty().addListener((obs, oldVal, newVal) -> {
      fileField.setDisable(!newVal);
      browseButton.setDisable(!newVal);
      interfaceComboBox.setDisable(newVal || interfaceComboBox.getItems().isEmpty());
    });

    loadAvailableInterfaces(interfaceComboBox, interfaceRadio, onError);

    GridPane sourceForm = new GridPane();
    sourceForm.setHgap(10);
    sourceForm.setVgap(8);
    sourceForm.add(new Label("Fonte:"), 0, 0);
    sourceForm.add(new HBox(10, fileRadio, interfaceRadio), 1, 0);
    sourceForm.add(new Label("Arquivo:"), 0, 1);
    sourceForm.add(buildFileBox(fileField, browseButton), 1, 1);
    sourceForm.add(new Label("Interface:"), 0, 2);
    sourceForm.add(interfaceComboBox, 1, 2);

    GridPane analysisForm = new GridPane();
    analysisForm.setHgap(10);
    analysisForm.setVgap(8);
    analysisForm.add(new Label("Port scan:"), 0, 0);
    analysisForm.add(portScanThresholdLabel, 1, 0);
    analysisForm.add(new Label("Janela:"), 0, 1);
    analysisForm.add(portScanWindowLabel, 1, 1);
    analysisForm.add(new Label("Fragmento mín (bytes):"), 0, 2);
    analysisForm.add(fragmentSpinner, 1, 2);

    HBox form = new HBox(30, sourceForm, analysisForm);
    HBox.setHgrow(sourceForm, Priority.ALWAYS);
    HBox.setHgrow(analysisForm, Priority.ALWAYS);

    HBox actions = new HBox(10, startButton, stopButton, clearButton);
    actions.setPadding(new Insets(10, 0, 0, 0));

    VBox topBox = new VBox(10, form, actions);
    topBox.setPadding(new Insets(12));

    TabPane tabPane = new TabPane();
    Tab alertTab = new Tab("Alertas", AlertTableFactory.create(model.getAlerts(), onDetails));
    Tab packetTab = new Tab("Pacotes", PacketTableFactory.create(model.getPackets()));
    alertTab.setClosable(false);
    packetTab.setClosable(false);
    tabPane.getTabs().addAll(alertTab, packetTab);

    HBox statsBar = new HBox(
        16,
        statusLabel,
        totalLabel,
        infoLabel,
        warnLabel,
        alertLabel,
        portScanLabel,
        fragmentationLabel);
    statsBar.setPadding(new Insets(10, 12, 12, 12));

    BorderPane root = new BorderPane();
    root.setTop(topBox);
    root.setCenter(tabPane);
    root.setBottom(statsBar);

    return new MainView(
        root,
        statusLabel,
        totalLabel,
        infoLabel,
        warnLabel,
        alertLabel,
        portScanLabel,
        fragmentationLabel,
        startButton,
        stopButton);
  }

  public void refreshStats(DashboardModel model) {
    totalLabel.setText("Pacotes: " + model.getPacketCount());
    infoLabel.setText("Info: " + model.getInfoCount());
    warnLabel.setText("Warn: " + model.getWarnCount());
    alertLabel.setText("Alert: " + model.getAlertCount());
    portScanLabel.setText("Port scan: " + model.getPortScanCount());
    fragmentationLabel.setText("Fragmentação: " + model.getFragmentationCount());
  }

  public void setRunning(boolean running) {
    statusLabel.setText("Status: " + (running ? "rodando" : "parado"));
    startButton.setDisable(running);
    stopButton.setDisable(!running);
  }

  private static CaptureRequest buildRequest(
      boolean fileSelected,
      boolean interfaceSelected,
      String filePath,
      String interfaceName,
      int fragmentMinSize) {
    String normalizedFile = filePath == null ? null : filePath.trim();
    if (fileSelected) {
      if (normalizedFile == null || normalizedFile.isEmpty()) {
        return null;
      }
      return new CaptureRequest(null, normalizedFile, fragmentMinSize);
    }
    if (interfaceSelected) {
      if (interfaceName == null || interfaceName.trim().isEmpty()) {
        return null;
      }
      return new CaptureRequest(interfaceName, null, fragmentMinSize);
    }
    return null;
  }

  private static HBox buildFileBox(TextField fileField, Button browseButton) {
    HBox box = new HBox(8, fileField, browseButton);
    HBox.setHgrow(fileField, Priority.ALWAYS);
    return box;
  }

  private static void chooseFile(Stage owner, TextField fileField) {
    FileChooser chooser = new FileChooser();
    chooser.setTitle("Selecionar arquivo PCAP");
    chooser.getExtensionFilters().add(
        new FileChooser.ExtensionFilter("PCAP", "*.pcap", "*.pcapng"));
    if (fileField.getText() != null && !fileField.getText().trim().isEmpty()) {
      File current = new File(fileField.getText().trim());
      if (current.getParentFile() != null && current.getParentFile().exists()) {
        chooser.setInitialDirectory(current.getParentFile());
      }
      chooser.setInitialFileName(current.getName());
    }
    File file = chooser.showOpenDialog(owner);
    if (file != null) {
      fileField.setText(file.getAbsolutePath());
    }
  }

  private static void loadAvailableInterfaces(
      ComboBox<String> interfaceComboBox,
      RadioButton interfaceRadio,
      Consumer<String> onError) {
    try {
      List<String> interfaces = NetworkInterfaceProvider.findAvailableInterfaces();
      if (interfaces.isEmpty()) {
        interfaceComboBox.getItems().clear();
        interfaceComboBox.setPromptText("Nenhuma interface encontrada");
        interfaceComboBox.setDisable(true);
        interfaceRadio.setDisable(true);
        return;
      }
      interfaceComboBox.getItems().setAll(interfaces);
      interfaceComboBox.getSelectionModel().selectFirst();
      interfaceRadio.setDisable(false);
    } catch (org.pcap4j.core.PcapNativeException ex) {
      interfaceComboBox.getItems().clear();
      interfaceComboBox.setPromptText("Falha ao carregar interfaces");
      interfaceComboBox.setDisable(true);
      interfaceRadio.setDisable(true);
      if (onError != null) {
        onError.accept("Falha ao listar interfaces disponíveis: " + ex.getMessage());
      }
    }
  }
}
