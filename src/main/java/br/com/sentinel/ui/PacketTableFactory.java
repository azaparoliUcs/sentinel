package br.com.sentinel.ui;

import br.com.sentinel.format.PacketFormatter;
import br.com.sentinel.model.PacketDTO;
import java.util.List;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import lombok.experimental.UtilityClass;

@UtilityClass
public final class PacketTableFactory {

  public static TableView<PacketDTO> create(ObservableList<PacketDTO> packets) {
    return buildTable(packets, "Nenhum pacote capturado ainda.");
  }

  public static TableView<PacketDTO> createRelated(List<PacketDTO> packets) {
    return buildTable(FXCollections.observableArrayList(packets),
        "Nenhum pacote relacionado foi armazenado para este alerta.");
  }

  private static TableView<PacketDTO> buildTable(
      ObservableList<PacketDTO> packets,
      String placeholderText) {
    TableView<PacketDTO> table = new TableView<>(packets);
    table.setPlaceholder(new Label(placeholderText));
    table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);

    TableColumn<PacketDTO, String> timeColumn = new TableColumn<>("Timestamp");
    timeColumn.setCellValueFactory(data -> new ReadOnlyStringWrapper(
        java.time.format.DateTimeFormatter.ISO_INSTANT.format(data.getValue().getTimestamp())));

    TableColumn<PacketDTO, String> protocolColumn = new TableColumn<>("Protocolo");
    protocolColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(PacketFormatter.nullSafe(data.getValue().getProtocol())));

    TableColumn<PacketDTO, String> sourceColumn = new TableColumn<>("Origem");
    sourceColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(PacketFormatter.formatEndpoint(
            data.getValue().getSourceIp(),
            data.getValue().getSourcePort())));

    TableColumn<PacketDTO, String> destinationColumn = new TableColumn<>("Destino");
    destinationColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(PacketFormatter.formatEndpoint(
            data.getValue().getDestinationIp(),
            data.getValue().getDestinationPort())));

    TableColumn<PacketDTO, String> descriptionColumn = new TableColumn<>("Descricao");
    descriptionColumn.setCellValueFactory(
        data -> new ReadOnlyStringWrapper(PacketFormatter.describePacket(data.getValue())));

    descriptionColumn.setMinWidth(320);
    table.getColumns().add(timeColumn);
    table.getColumns().add(protocolColumn);
    table.getColumns().add(sourceColumn);
    table.getColumns().add(destinationColumn);
    table.getColumns().add(descriptionColumn);
    return table;
  }
}
