/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util.logging;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 * Helpers for safely including untrusted or potentially sensitive text, such as remote HTTP response bodies, in log
 * statements. Prefer logging opaque identifiers and status codes; use this only when a payload excerpt is genuinely
 * needed for diagnosis.
 */
public final class LogSanitizer {

  static final String MASK = "***";
  static final int DEFAULT_MAX_LENGTH = 256;

  private static final String PLACEHOLDER_NULL = "<null>";

  // Matches JSON string values for keys that commonly carry secrets or personal data, e.g. "token": "abc"
  private static final Pattern SENSITIVE_JSON_FIELD = Pattern.compile(
      "(\"(?:[^\"\\\\]*(?:token|key|secret|password|passwd|credential|auth|signature|hmac|phone|number|e164|code|message|body)[^\"\\\\]*)\"\\s*:\\s*)\"(?:[^\"\\\\]|\\\\.)*\"",
      Pattern.CASE_INSENSITIVE);

  // Matches e164 style phone numbers appearing anywhere in free text
  private static final Pattern E164 = Pattern.compile("\\+\\d{7,15}");

  private static final Pattern CONTROL_CHARACTERS = Pattern.compile("[\\p{Cntrl}&&[^ ]]");

  private LogSanitizer() {
  }

  /**
   * Equivalent to {@link #sanitize(String, int)} with a default maximum length.
   */
  public static String sanitize(@Nullable final String value) {
    return sanitize(value, DEFAULT_MAX_LENGTH);
  }

  /**
   * Returns a form of the given text that is safe to log: values of sensitive-looking JSON fields and e164 phone
   * numbers are masked, control characters (including line breaks, which enable log forging) are replaced, and the
   * result is truncated to the given maximum length.
   *
   * @param value the text to sanitize; may be {@code null}
   * @param maxLength the maximum length of the returned text, excluding the truncation marker
   *
   * @return the sanitized text
   */
  public static String sanitize(@Nullable final String value, final int maxLength) {
    if (value == null) {
      return PLACEHOLDER_NULL;
    }

    String sanitized = SENSITIVE_JSON_FIELD.matcher(value)
        .replaceAll(match -> Matcher.quoteReplacement(match.group(1) + "\"" + MASK + "\""));

    sanitized = E164.matcher(sanitized).replaceAll(MASK);
    sanitized = CONTROL_CHARACTERS.matcher(sanitized).replaceAll("_");

    if (sanitized.length() > maxLength) {
      sanitized = sanitized.substring(0, Math.max(0, maxLength)) + "...[truncated]";
    }

    return sanitized;
  }
}
