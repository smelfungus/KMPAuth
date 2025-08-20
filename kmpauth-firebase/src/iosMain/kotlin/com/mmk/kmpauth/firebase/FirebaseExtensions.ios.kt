package com.mmk.kmpauth.firebase

import com.mmk.kmpauth.core.FirebaseAuthErrorType
import dev.gitlive.firebase.auth.FirebaseAuthException

public actual fun getAuthErrorType(e: FirebaseAuthException): FirebaseAuthErrorType {
    val message = e.message ?: return FirebaseAuthErrorType.UNKNOWN
    return when {
        message.contains("User has already been linked to the given provider.") -> {
            FirebaseAuthErrorType.PROVIDER_ALREADY_LINKED
        }

        message.contains("This credential is already associated with a different user account.") -> {
            FirebaseAuthErrorType.CREDENTIAL_ALREADY_IN_USE
        }

        message.contains("An account already exists with the same email address but different sign-in credentials. Sign in using a provider associated with this email address.") -> {
            FirebaseAuthErrorType.ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL
        }

        else -> {
            return FirebaseAuthErrorType.UNKNOWN
        }
    }
}
