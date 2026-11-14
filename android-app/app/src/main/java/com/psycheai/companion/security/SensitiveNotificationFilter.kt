package com.psycheai.companion.security

/**
 * Pre-persistence OTP, authenticator, UPI, Aadhaar, and banking transaction filter.
 * Executed synchronously in PsycheNotificationListenerService before touching SQLite or network.
 */
object SensitiveNotificationFilter {

    val DEFAULT_ALLOWED_PACKAGES: Set<String> = setOf(
        "com.whatsapp",
        "org.telegram.messenger",
        "org.thoughtcrime.securesms",
        "com.google.android.apps.messaging",
        "com.instagram.android",
    )

    private val SENSITIVE_PACKAGES: Set<String> = setOf(
        "com.google.android.apps.authenticator2",
        "com.azure.authenticator",
        "com.duosecurity.duomobile",
    )

    private val OTP_PATTERNS: List<Regex> = listOf(
        Regex(
            """\b\d{4,8}\b.*\b(?:otp|verification\s+code|one[\s-]?time\s+password|security\s+code|do\s+not\s+share|valid\s+for\s+\d+\s*min|bank|upi|aadhaar)\b""",
            setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
        ),
        Regex(
            """\b(?:otp|verification\s+code|one[\s-]?time\s+password|security\s+code|bank|upi|aadhaar)\b.*\b\d{4,8}\b""",
            setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
        ),
        Regex(
            """\b(?:a/c|acct|account)\s*[xX\*]+\d{3,4}\s*(?:debited|credited)\b""",
            setOf(RegexOption.IGNORE_CASE),
        ),
    )

    fun isPackageAllowed(packageName: String, allowlist: Set<String> = DEFAULT_ALLOWED_PACKAGES): Boolean {
        return packageName in allowlist && packageName !in SENSITIVE_PACKAGES
    }

    fun isSensitiveOrOtpNotification(rawText: String, packageName: String = ""): Boolean {
        if (packageName in SENSITIVE_PACKAGES) {
            return true
        }
        return OTP_PATTERNS.any { it.containsMatchIn(rawText) }
    }
}
