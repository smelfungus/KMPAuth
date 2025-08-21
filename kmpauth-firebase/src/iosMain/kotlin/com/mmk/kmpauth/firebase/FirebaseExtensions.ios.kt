@file:OptIn(ExperimentalForeignApi::class)

package com.mmk.kmpauth.firebase

import cocoapods.FirebaseAuth.FIRAuthErrorDomain
import cocoapods.FirebaseAuth.FIRAuthErrorUserInfoNameKey
import com.mmk.kmpauth.core.FirebaseAuthErrorType
import dev.gitlive.firebase.auth.FirebaseAuthException
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSError

public actual fun getAuthErrorType(e: FirebaseAuthException): FirebaseAuthErrorType {
    val nsError = (e.cause as? NSError)
    return if (nsError != null && nsError.domain == FIRAuthErrorDomain) {
        val stringErrorCode = nsError.userInfo[FIRAuthErrorUserInfoNameKey] as? String
        if (stringErrorCode != null) {
            when (stringErrorCode) {
                "ERROR_PROVIDER_ALREADY_LINKED" -> {
                    FirebaseAuthErrorType.PROVIDER_ALREADY_LINKED
                }

                "ERROR_CREDENTIAL_ALREADY_IN_USE" -> {
                    FirebaseAuthErrorType.CREDENTIAL_ALREADY_IN_USE
                }

                "ERROR_ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL" -> {
                    FirebaseAuthErrorType.ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL
                }

                else -> {
                    FirebaseAuthErrorType.UNKNOWN
                }
            }
        } else {
            val errorCode = nsError.code
            when (errorCode) {
                17015L -> FirebaseAuthErrorType.PROVIDER_ALREADY_LINKED
                17025L -> FirebaseAuthErrorType.CREDENTIAL_ALREADY_IN_USE
                17012L -> FirebaseAuthErrorType.ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL
                else -> FirebaseAuthErrorType.UNKNOWN
            }
        }
    } else {
        // Fallback
        val message = e.message ?: return FirebaseAuthErrorType.UNKNOWN
        when {
            message.contains("User has already been linked to the given provider.")
                    || message.contains("User can only be linked to one identity for the given provider.")
                    || message.contains("ERROR_PROVIDER_ALREADY_LINKED") -> {
                FirebaseAuthErrorType.PROVIDER_ALREADY_LINKED
            }

            message.contains("This credential is already associated with a different user account.")
                    || message.contains("ERROR_CREDENTIAL_ALREADY_IN_USE") -> {
                FirebaseAuthErrorType.CREDENTIAL_ALREADY_IN_USE
            }

            message.contains("An account already exists with the same email address but different sign-in credentials. Sign in using a provider associated with this email address.")
                    || message.contains("ERROR_ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL") -> {
                FirebaseAuthErrorType.ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL
            }

            else -> {
                return FirebaseAuthErrorType.UNKNOWN
            }
        }
    }
}
