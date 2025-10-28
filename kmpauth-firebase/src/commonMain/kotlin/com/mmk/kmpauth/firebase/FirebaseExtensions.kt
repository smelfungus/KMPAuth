package com.mmk.kmpauth.firebase

import com.mmk.kmpauth.core.FirebaseAuthErrorType
import dev.gitlive.firebase.auth.FirebaseAuthException

public expect fun getAuthErrorType(e: FirebaseAuthException): FirebaseAuthErrorType

public fun getAuthErrorType(code: Long): FirebaseAuthErrorType {
    return when (code) {
        17015L -> FirebaseAuthErrorType.PROVIDER_ALREADY_LINKED
        17025L -> FirebaseAuthErrorType.CREDENTIAL_ALREADY_IN_USE
        17012L -> FirebaseAuthErrorType.ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL
        else -> FirebaseAuthErrorType.UNKNOWN
    }
}
