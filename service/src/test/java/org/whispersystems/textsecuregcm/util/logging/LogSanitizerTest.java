/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util.logging;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

  @Test
  void nullValue() {
    assertThat(LogSanitizer.sanitize(null)).isEqualTo("<null>");
  }

  @Test
  void masksSensitiveJsonFields() {
    final String sanitized = LogSanitizer.sanitize(
        "{\"error\":\"bad\",\"accessToken\":\"abc123\",\"hmacKey\":\"s3cr3t\",\"phoneNumber\":\"+14155550123\"}");

    assertThat(sanitized)
        .contains("\"error\":\"bad\"")
        .contains("\"accessToken\":\"***\"")
        .contains("\"hmacKey\":\"***\"")
        .contains("\"phoneNumber\":\"***\"")
        .doesNotContain("abc123", "s3cr3t", "4155550123");
  }

  @Test
  void masksPhoneNumbersInFreeText() {
    assertThat(LogSanitizer.sanitize("failed for +14155550123 today"))
        .isEqualTo("failed for *** today");
  }

  @Test
  void replacesControlCharacters() {
    assertThat(LogSanitizer.sanitize("line one\r\nINFO forged entry"))
        .doesNotContain("\r", "\n");
  }

  @Test
  void truncatesLongValues() {
    assertThat(LogSanitizer.sanitize("a".repeat(50), 10)).isEqualTo("a".repeat(10) + "...[truncated]");
  }

  @Test
  void leavesBenignValuesAlone() {
    assertThat(LogSanitizer.sanitize("{\"status\":\"ok\"}")).isEqualTo("{\"status\":\"ok\"}");
  }
}
