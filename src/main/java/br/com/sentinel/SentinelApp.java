package br.com.sentinel;

import br.com.sentinel.capture.CaptureController;
import br.com.sentinel.capture.CaptureRequest;
import br.com.sentinel.ui.AlertDetailWindow;
import br.com.sentinel.ui.DashboardModel;
import br.com.sentinel.ui.MainView;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.stage.Stage;

public class SentinelApp extends Application {

  private final DashboardModel model = new DashboardModel();
  private final CaptureController captureController = new CaptureController();

  private Stage primaryStage;
  private MainView mainView;

  public static void main(String[] args) {
    launch(args);
  }

  @Override
  public void start(Stage stage) {
    primaryStage = stage;
    mainView = MainView.create(
        stage,
        model,
        this::startCapture,
        this::stopCapture,
        this::clearDashboard,
        alert -> AlertDetailWindow.show(primaryStage, alert),
        this::showError);
    mainView.refreshStats(model);
    mainView.setRunning(false);

    Scene scene = new Scene(mainView.getRoot(), 1100, 650);
    stage.setTitle("Pcap4J Security Analyzer");
    stage.setScene(scene);
    stage.show();
  }

  @Override
  public void stop() {
    captureController.shutdown();
  }

  private void startCapture(CaptureRequest request) {
    if (request == null) {
      showError("Informe a fonte correta antes de iniciar.");
      return;
    }

    mainView.setRunning(true);
    captureController.startCapture(
        request.interfaceName(),
        request.filePath(),
        request.fragmentMinSize(),
        alert -> Platform.runLater(() -> {
          model.addAlert(alert);
          mainView.refreshStats(model);
        }),
        packet -> Platform.runLater(() -> {
          model.addPacket(packet);
          mainView.refreshStats(model);
        }),
        message -> Platform.runLater(() -> {
          showError(message);
          mainView.setRunning(false);
        }),
        () -> Platform.runLater(() -> mainView.setRunning(false)));
  }

  private void stopCapture() {
    captureController.stopCapture();
    if (mainView != null) {
      mainView.setRunning(false);
    }
  }

  private void clearDashboard() {
    model.clear();
    if (mainView != null) {
      mainView.refreshStats(model);
    }
  }

  private void showError(String message) {
    Alert alert = new Alert(Alert.AlertType.ERROR);
    alert.setTitle("Erro");
    alert.setHeaderText("Falha na execução");
    alert.setContentText(message);
    alert.showAndWait();
  }
}
