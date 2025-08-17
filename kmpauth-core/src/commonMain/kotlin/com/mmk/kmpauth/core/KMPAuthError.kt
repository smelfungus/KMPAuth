package com.mmk.kmpauth.core

public class KMPAuthError(
    public val type: KMPAuthErrorType,
    cause: Throwable? = null
) : Exception(cause)

public enum class KMPAuthErrorType {
    UNKNOWN,
    UI,
    USER_CANCELLED,
    NO_ID_TOKEN,
    NO_FIREBASE_USER,
}
