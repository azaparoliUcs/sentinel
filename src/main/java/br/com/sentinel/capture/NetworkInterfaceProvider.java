package br.com.sentinel.capture;

import java.util.List;
import lombok.experimental.UtilityClass;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

@UtilityClass
public final class NetworkInterfaceProvider {

  public static List<String> findAvailableInterfaces() throws PcapNativeException {
    List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
    if (devices == null || devices.isEmpty()) {
      return List.of();
    }
    return devices.stream()
        .map(PcapNetworkInterface::getName)
        .filter(name -> name != null && !name.isBlank())
        .toList();
  }
}
