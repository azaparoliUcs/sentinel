package br.com.sentinel.ui;

import br.com.sentinel.format.PacketFormatter;
import br.com.sentinel.model.AlertEvent;
import java.util.function.Consumer;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.collections.ObservableList;
import javafx.scene.control.Button;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import lombok.experimental.UtilityClass;

@UtilityClass
public final class AlertTableFactory {

  public static TableView<AlertEvent> create(
      ObservableList<AlertEvent> alerts,
      Consumer<AlertEvent> onDetailsRequested) {
    TableView<AlertEvent> table = new TableView<>(alerts);
    table.setPlaceholder(new javafx.scene.control.Label("Nenhum alerta gerado ainda."));
    table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);

    TableColumn<AlertEvent, String> timeColumn = new TableColumn<>("Timestamp");
    timeColumn.setCellValueFactory(data -> new ReadOnlyStringWrapper(
        java.time.format.DateTimeFormatter.ISO_INSTANT.format(data.getValue().getTimestamp())));

    TableColumn<AlertEvent, String> severityColumn = new TableColumn<>("Severidade");
    severityColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(data.getValue().getSeverity().name()));

    TableColumn<AlertEvent, String> typeColumn = new TableColumn<>("Tipo");
    typeColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(data.getValue().getType().name()));

    TableColumn<AlertEvent, String> sourceColumn = new TableColumn<>("Origem");
    sourceColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(PacketFormatter.nullSafe(data.getValue().getSourceIp())));

    TableColumn<AlertEvent, String> destinationColumn = new TableColumn<>("Destino");
    destinationColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(PacketFormatter.nullSafe(data.getValue().getDestinationIp())));

    TableColumn<AlertEvent, String> descriptionColumn = new TableColumn<>("Descricao");
    descriptionColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(data.getValue().getDescription()));
    descriptionColumn.setMinWidth(300);

    TableColumn<AlertEvent, Void> actionColumn = new TableColumn<>("Ações");
    actionColumn.setMinWidth(110);
    actionColumn.setMaxWidth(110);
    actionColumn.setResizable(false);
    actionColumn.setCellFactory(col -> new TableCell<>() {
      private final Button detailsButton = new Button("Detalhes");

      {
        detailsButton.setOnAction(event -> {
          AlertEvent alert = getTableRow() == null ? null : getTableRow().getItem();
          if (alert != null && onDetailsRequested != null) {
            onDetailsRequested.accept(alert);
          }
        });
      }

      @Override
      protected void updateItem(Void item, boolean empty) {
        super.updateItem(item, empty);
        setText(null);
        setGraphic(empty ? null : detailsButton);
      }
    });

    table.getColumns().add(timeColumn);
    table.getColumns().add(severityColumn);
    table.getColumns().add(typeColumn);
    table.getColumns().add(sourceColumn);
    table.getColumns().add(destinationColumn);
    table.getColumns().add(descriptionColumn);
    table.getColumns().add(actionColumn);
    return table;
  }
}
