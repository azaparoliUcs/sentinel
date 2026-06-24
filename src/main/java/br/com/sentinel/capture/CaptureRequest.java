package br.com.sentinel.capture;

public record CaptureRequest(String interfaceName, String filePath, int fragmentMinSize) {
}
