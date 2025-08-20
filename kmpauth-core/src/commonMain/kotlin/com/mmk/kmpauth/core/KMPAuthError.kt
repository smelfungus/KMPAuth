package com.mmk.kmpauth.core

public class KMPAuthError(
    public val type: KMPAuthErrorType,
    message: String? = null,
    cause: Throwable? = null
) : Exception(message, cause)

public enum class KMPAuthErrorType {
    UNKNOWN,
    UI,
    USER_CANCELLED,
    NO_ID_TOKEN,
    NO_FIREBASE_USER,
    PROVIDER_ALREADY_LINKED,
    CREDENTIAL_ALREADY_IN_USE,
    ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL,
}

public enum class FirebaseAuthErrorType {
    UNKNOWN,
    PROVIDER_ALREADY_LINKED,
    CREDENTIAL_ALREADY_IN_USE,
    ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL,
}
