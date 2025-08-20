package com.mmk.kmpauth.firebase.google

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import com.mmk.kmpauth.core.FirebaseAuthErrorType
import com.mmk.kmpauth.core.KMPAuthError
import com.mmk.kmpauth.core.KMPAuthErrorType
import com.mmk.kmpauth.core.KMPAuthInternalApi
import com.mmk.kmpauth.core.UiContainerScope
import com.mmk.kmpauth.core.logger.currentLogger
import com.mmk.kmpauth.firebase.getAuthErrorType
import com.mmk.kmpauth.google.GoogleButtonUiContainer
import dev.gitlive.firebase.Firebase
import dev.gitlive.firebase.auth.FirebaseAuthException
import dev.gitlive.firebase.auth.FirebaseUser
import dev.gitlive.firebase.auth.GoogleAuthProvider
import dev.gitlive.firebase.auth.auth
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/**
 * GoogleSignInButton Ui Container Composable that handles all sign-in functionality for Google.
 * Child of this Composable can be any view or Composable function.
 * You need to call [UiContainerScope.onClick] function on your child view's click function.
 *
 * @param linkAccount Default value is false
 * @param filterByAuthorizedAccounts set to true so users can choose between available accounts to sign in.
 * @param scopes Custom scopes to retrieve more information. Default value listOf("email", "profile")
 * [onResult] callback will return [Result] with [FirebaseUser] type.
 *
 * Example Usage:
 * ```
 * //Github Sign-In with Custom Button and authentication with Firebase
 * GoogleButtonUiContainerFirebase(onResult = onFirebaseResult) {
 *     Button(onClick = { this.onClick() }) { Text("Google Sign-In (Custom Design)") }
 * }
 *
 * ```
 *
 */
@OptIn(KMPAuthInternalApi::class)
@Composable
public fun GoogleButtonUiContainerFirebase(
    modifier: Modifier = Modifier,
    linkAccount: Boolean = false,
    filterByAuthorizedAccounts: Boolean = false,
    scopes: List<String> = listOf("email", "profile"),
    onResult: (Result<FirebaseUser?>) -> Unit,
    content: @Composable UiContainerScope.() -> Unit,
) {
    val updatedOnResult by rememberUpdatedState(onResult)
    val coroutineScope = rememberCoroutineScope()
    GoogleButtonUiContainer(
        modifier = modifier,
        filterByAuthorizedAccounts = filterByAuthorizedAccounts,
        scopes = scopes,
        onGoogleSignInResult = { googleUser ->
            val idToken = googleUser?.idToken
            val accessToken = googleUser?.accessToken
            if (idToken == null) {
                currentLogger.log("Google idToken is null")
                updatedOnResult(
                    Result.failure(
                        KMPAuthError(
                            type = KMPAuthErrorType.NO_ID_TOKEN,
                            cause = null,
                        )
                    )
                )
                return@GoogleButtonUiContainer
            }
            val authCredential = GoogleAuthProvider.credential(idToken, accessToken)
            coroutineScope.launch {
                try {
                    val auth = Firebase.auth
                    val currentUser = auth.currentUser
                    val result = if (linkAccount && currentUser != null) {
                        currentUser.linkWithCredential(authCredential)
                    } else {
                        auth.signInWithCredential(authCredential)
                    }
                    if (result.user == null) {
                        currentLogger.log("Firebase user is null")
                        updatedOnResult(
                            Result.failure(
                                KMPAuthError(
                                    type = KMPAuthErrorType.NO_FIREBASE_USER,
                                    cause = null,
                                )
                            )
                        )
                    } else {
                        updatedOnResult(Result.success(result.user))
                    }
                } catch (e: Exception) {
                    if (e is CancellationException) throw e

                    when (e) {
                        is FirebaseAuthException -> {
                            val errorType = getAuthErrorType(e)
                            when (errorType) {
                                FirebaseAuthErrorType.UNKNOWN -> {
                                    currentLogger.log("Google sign-in failed with exception: $e")
                                    updatedOnResult(
                                        Result.failure(
                                            KMPAuthError(
                                                type = KMPAuthErrorType.UNKNOWN,
                                                cause = e,
                                            )
                                        )
                                    )
                                }

                                FirebaseAuthErrorType.PROVIDER_ALREADY_LINKED -> {
                                    // Provider already linked to THIS user → treat as success (no-op)
                                    val user = Firebase.auth.currentUser
                                    updatedOnResult(Result.success(user))
                                }

                                FirebaseAuthErrorType.CREDENTIAL_ALREADY_IN_USE -> {
                                    // Credential belongs to ANOTHER Firebase user
                                    if (linkAccount) {
                                        try {
                                            val signedIn =
                                                Firebase.auth.signInWithCredential(authCredential)
                                            updatedOnResult(Result.success(signedIn.user))
                                        } catch (signInError: Exception) {
                                            if (signInError is CancellationException) throw signInError
                                            currentLogger.log("Google sign-in failed with existing account: ${signInError.message}")
                                            updatedOnResult(
                                                Result.failure(
                                                    KMPAuthError(
                                                        type = KMPAuthErrorType.UNKNOWN,
                                                        cause = signInError,
                                                    )
                                                )
                                            )
                                        }
                                    } else {
                                        currentLogger.log("Google sign-in failed with error message: ${e.message}")
                                        updatedOnResult(
                                            Result.failure(
                                                KMPAuthError(
                                                    type = KMPAuthErrorType.UNKNOWN,
                                                    cause = e,
                                                )
                                            )
                                        )
                                    }
                                }

                                FirebaseAuthErrorType.ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL -> {
                                    currentLogger.log("Google sign-in failed with error: ${e.message}")
                                    updatedOnResult(
                                        Result.failure(
                                            KMPAuthError(
                                                type = KMPAuthErrorType.ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL,
                                                cause = e,
                                            )
                                        )
                                    )
                                }
                            }
                        }

                        else -> {
                            currentLogger.log("Google sign-in failed with exception: $e")
                            updatedOnResult(
                                Result.failure(
                                    KMPAuthError(
                                        type = KMPAuthErrorType.UNKNOWN,
                                        cause = e,
                                    )
                                )
                            )
                        }
                    }
                }
            }
        },
        content = content,
    )
}

@Deprecated(
    "Use GoogleButtonUiContainerFirebase with linkAccount and filterByAuthorizedAccounts parameters, which defaults to false",
    ReplaceWith(""),
    DeprecationLevel.WARNING
)
@Composable
public fun GoogleButtonUiContainerFirebase(
    modifier: Modifier = Modifier,
    onResult: (Result<FirebaseUser?>) -> Unit,
    content: @Composable UiContainerScope.() -> Unit,
) {
    GoogleButtonUiContainerFirebase(
        modifier = modifier,
        linkAccount = false,
        filterByAuthorizedAccounts = false,
        onResult = onResult,
        content = content,
    )
}
