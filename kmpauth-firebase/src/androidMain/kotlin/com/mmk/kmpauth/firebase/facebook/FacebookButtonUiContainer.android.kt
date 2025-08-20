package com.mmk.kmpauth.firebase.facebook

import android.app.Activity
import android.content.Intent
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.facebook.CallbackManager
import com.facebook.FacebookCallback
import com.facebook.FacebookException
import com.facebook.login.LoginManager
import com.facebook.login.LoginResult
import com.mmk.kmpauth.core.FirebaseAuthErrorType
import com.mmk.kmpauth.core.KMPAuth
import com.mmk.kmpauth.core.KMPAuthError
import com.mmk.kmpauth.core.KMPAuthErrorType
import com.mmk.kmpauth.core.KMPAuthInternalApi
import com.mmk.kmpauth.core.UiContainerScope
import com.mmk.kmpauth.core.getActivity
import com.mmk.kmpauth.core.logger.currentLogger
import com.mmk.kmpauth.firebase.domain.FacebookCredentialPayload
import com.mmk.kmpauth.firebase.domain.FacebookSignInResult
import com.mmk.kmpauth.firebase.getAuthErrorType

import dev.gitlive.firebase.Firebase
import dev.gitlive.firebase.auth.FacebookAuthProvider
import dev.gitlive.firebase.auth.FirebaseAuthException
import dev.gitlive.firebase.auth.auth
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlin.coroutines.cancellation.CancellationException


/**
 * You mush call `KMPAuth.handleFacebookActivityResult` from your Activity's onActivityResult to handle Facebook login.
 *
 * Example:
 * ```
 * override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
 *   super.onActivityResult(requestCode, resultCode, data)
 *   KMPAuth.handleFacebookActivityResult(requestCode, resultCode, data)
 * }
 * ```
 */
public fun KMPAuth.handleFacebookActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    facebookLoginCallbackManager.onActivityResult(requestCode, resultCode, data)
}


private val facebookLoginCallbackManager: CallbackManager by lazy { CallbackManager.Factory.create() }

private val loginManager: LoginManager by lazy { LoginManager.getInstance() }

@OptIn(KMPAuthInternalApi::class)
@Composable
public actual fun FacebookButtonUiContainer(
    modifier: Modifier,
    requestScopes: List<FacebookSignInRequestScope>,
    onResult: (Result<FacebookSignInResult?>) -> Unit,
    linkAccount: Boolean,
    content: @Composable (UiContainerScope.() -> Unit)
) {
    val updatedOnResult by rememberUpdatedState(onResult)
    val coroutineScope = rememberCoroutineScope()
    val activity = LocalContext.current.getActivity()

    DisposableEffect(Unit) {
        loginManager.registerCallback(
            facebookLoginCallbackManager,
            facebookSignInCallback(coroutineScope, linkAccount, updatedOnResult)
        )

        onDispose {
            loginManager.unregisterCallback(facebookLoginCallbackManager)
        }
    }

    val permissions: List<String> = requestScopes.map {
        when (it) {
            FacebookSignInRequestScope.Email -> "email"
            FacebookSignInRequestScope.PublicProfile -> "public_profile"
        }
    }

    val uiContainerScope = remember {
        object : UiContainerScope {
            override fun onClick() {
                if (activity == null) {
                    updatedOnResult(Result.failure(KMPAuthError(type = KMPAuthErrorType.UI)))
                    return
                }
                // Prevent stale session issues
                loginManager.logOut()
                loginManager.logInWithReadPermissions(activity as Activity, permissions)
            }
        }
    }
    Box(modifier = modifier) { uiContainerScope.content() }
}

@OptIn(KMPAuthInternalApi::class)
private fun facebookSignInCallback(
    coroutineScope: CoroutineScope,
    linkAccount: Boolean,
    updatedOnResult: (Result<FacebookSignInResult?>) -> Unit
): FacebookCallback<LoginResult> = object : FacebookCallback<LoginResult> {
    override fun onSuccess(result: LoginResult) {
        currentLogger.log("Facebook Login successful, attempting to sign in with Firebase")
        val accessToken = result.accessToken.token
        val userId = result.accessToken.userId
        val authCredential = FacebookAuthProvider.credential(accessToken)
        coroutineScope.launch {
            try {
                val auth = Firebase.auth
                val currentUser = auth.currentUser

                if (linkAccount && currentUser != null) {
                    val linked =
                        currentUser.providerData.firstOrNull { it.providerId == "facebook.com" }
                    if (linked != null) {
                        // Already linked
                        if (linked.uid == userId) {
                            // Same FB account → success (no-op)
                            updatedOnResult(
                                Result.success(
                                    FacebookSignInResult(
                                        user = currentUser,
                                        credential = FacebookCredentialPayload.AccessToken(
                                            token = accessToken,
                                        ),
                                    ),
                                )
                            )
                            return@launch
                        } else {
                            // TODO: Handle different FB account is already linked
                        }
                    }
                }

                val firebaseAuthResult = if (linkAccount && currentUser != null) {
                    currentLogger.log("Linking Facebook account with current Firebase user: ${currentUser.uid}")
                    currentUser.linkWithCredential(authCredential)
                } else {
                    currentLogger.log("Signing in with Facebook account on Firebase")
                    auth.signInWithCredential(authCredential)
                }
                val user = firebaseAuthResult.user
                if (user == null) {
                    currentLogger.log("Facebook sign-in failed with error: Firebase user is null")
                    updatedOnResult(Result.failure(KMPAuthError(type = KMPAuthErrorType.NO_FIREBASE_USER)))
                } else {
                    currentLogger.log("Facebook sign-in successful")
                    val result = FacebookSignInResult(
                        user = user,
                        credential = FacebookCredentialPayload.AccessToken(token = accessToken),
                    )
                    updatedOnResult(Result.success(result))
                }
            } catch (e: Exception) {
                if (e is CancellationException) throw e

                when (e) {
                    is FirebaseAuthException -> {
                        val errorType = getAuthErrorType(e)
                        when (errorType) {
                            FirebaseAuthErrorType.UNKNOWN -> {
                                currentLogger.log("Facebook sign-in failed with error code: ${e.errorCode}, message: ${e.message}")
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
                                updatedOnResult(
                                    Result.success(
                                        FacebookSignInResult(
                                            user = user,
                                            credential = FacebookCredentialPayload.AccessToken(
                                                token = accessToken,
                                            ),
                                        )
                                    )
                                )
                            }

                            FirebaseAuthErrorType.CREDENTIAL_ALREADY_IN_USE -> {
                                // Credential belongs to ANOTHER Firebase user
                                if (linkAccount) {
                                    try {
                                        val signedIn =
                                            Firebase.auth.signInWithCredential(authCredential)
                                        updatedOnResult(
                                            Result.success(
                                                FacebookSignInResult(
                                                    user = signedIn.user,
                                                    credential = FacebookCredentialPayload.AccessToken(
                                                        token = accessToken,
                                                    ),
                                                )
                                            )
                                        )
                                    } catch (signInError: Exception) {
                                        if (signInError is CancellationException) throw signInError
                                        currentLogger.log("Facebook sign-in failed with existing account: ${signInError.message}")
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
                                    currentLogger.log("Facebook sign-in failed with error code: ${e.errorCode}, message: ${e.message}")
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
                                currentLogger.log("Facebook sign-in failed with error: ${e.message}")
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
                        currentLogger.log("Facebook sign-in failed with error: ${e.message}")
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
    }

    override fun onCancel() {
        updatedOnResult(Result.failure(KMPAuthError(type = KMPAuthErrorType.USER_CANCELLED)))
    }

    override fun onError(error: FacebookException) {
        updatedOnResult(
            Result.failure(
                KMPAuthError(
                    type = KMPAuthErrorType.UNKNOWN,
                    cause = error,
                )
            )
        )
    }
}