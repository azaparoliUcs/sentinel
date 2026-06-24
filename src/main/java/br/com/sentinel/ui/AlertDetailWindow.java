package br.com.sentinel.ui;

import br.com.sentinel.format.AlertFormatter;
import br.com.sentinel.model.AlertEvent;
import br.com.sentinel.model.PacketDTO;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import lombok.experimental.UtilityClass;

@UtilityClass
public final class AlertDetailWindow {

  public static void show(Stage owner, AlertEvent alert) {
    if (alert == null) {
      return;
    }

    Stage detailStage = new Stage();
    if (owner != null) {
      detailStage.initOwner(owner);
    }
    detailStage.initModality(Modality.NONE);
    detailStage.setTitle("Detalhamento - " + alert.getType().name());

    TextArea summaryArea = new TextArea(AlertFormatter.buildAlertSummary(alert));
    summaryArea.setEditable(false);
    summaryArea.setWrapText(true);
    summaryArea.setFocusTraversable(false);
    summaryArea.setPrefRowCount(8);

    TableView<PacketDTO> relatedPacketTable = PacketTableFactory.createRelated(alert.getRelatedPackets());

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
}
