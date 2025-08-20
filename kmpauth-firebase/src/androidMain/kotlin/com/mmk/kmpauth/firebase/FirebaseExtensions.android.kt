package com.mmk.kmpauth.firebase

import com.mmk.kmpauth.core.FirebaseAuthErrorType
import dev.gitlive.firebase.auth.FirebaseAuthException

public actual fun getAuthErrorType(e: FirebaseAuthException): FirebaseAuthErrorType {
    return when (e.errorCode) {
        "ERROR_PROVIDER_ALREADY_LINKED" -> FirebaseAuthErrorType.PROVIDER_ALREADY_LINKED
        "ERROR_CREDENTIAL_ALREADY_IN_USE" -> FirebaseAuthErrorType.CREDENTIAL_ALREADY_IN_USE
        "ERROR_ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL" -> FirebaseAuthErrorType.ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL
        else -> FirebaseAuthErrorType.UNKNOWN
    }
}
