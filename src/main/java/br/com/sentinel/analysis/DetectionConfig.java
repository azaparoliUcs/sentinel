package br.com.sentinel.analysis;

import lombok.experimental.UtilityClass;

@UtilityClass
public final class DetectionConfig {

  public static final int PORT_SCAN_THRESHOLD = 20;
  public static final int PORT_SCAN_WINDOW_SECONDS = 60;
  public static final int DEFAULT_FRAGMENT_MIN_SIZE = 400;
}
