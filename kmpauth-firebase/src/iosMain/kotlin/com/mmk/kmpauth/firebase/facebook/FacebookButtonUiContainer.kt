package com.mmk.kmpauth.firebase.facebook

import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import cocoapods.FBSDKLoginKit.FBSDKLoginConfiguration
import cocoapods.FBSDKLoginKit.FBSDKLoginManager
import cocoapods.FBSDKLoginKit.FBSDKLoginTrackingLimited
import com.mmk.kmpauth.core.KMPAuthInternalApi
import com.mmk.kmpauth.core.UiContainerScope
import com.mmk.kmpauth.core.logger.currentLogger
import com.mmk.kmpauth.firebase.domain.FacebookCredentialPayload
import com.mmk.kmpauth.firebase.domain.FacebookSignInResult
import dev.gitlive.firebase.Firebase
import dev.gitlive.firebase.auth.FirebaseUser
import dev.gitlive.firebase.auth.OAuthProvider
import dev.gitlive.firebase.auth.auth
import io.ktor.util.generateNonce
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.refTo
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.launch
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.UIKit.UIApplication
import platform.UIKit.UIWindow
import platform.UIKit.UIWindowScene
import kotlin.coroutines.cancellation.CancellationException

/**
 * FacebookButton Ui Container Composable that handles all sign-in functionality for Facebook.
 * Child of this Composable can be any view or Composable function.
 * You need to call [UiContainerScope.onClick] function on your child view's click function.
 *
 * [onResult] callback will return [Result] with [FirebaseUser] type.
 * @param requestScopes list of request scopes type of [FacebookSignInRequestScope].
 * @param linkAccount if true, it will link the account with the current user. Default value is false
 * Example Usage:
 * ```
 * //Facebook Sign-In with Custom Button and authentication with Firebase
 * FacebookButtonUiContainer(onResult = onFirebaseResult) {
 *     Button(onClick = { this.onClick() }) { Text("Facebook Sign-In (Custom Design)") }
 * }
 *
 * ```
 *
 */
@OptIn(ExperimentalForeignApi::class, KMPAuthInternalApi::class)
@Composable
public actual fun FacebookButtonUiContainer(
    modifier: Modifier,
    requestScopes: List<FacebookSignInRequestScope>,
    onResult: (Result<FacebookSignInResult?>) -> Unit,
    linkAccount: Boolean,
    content: @Composable UiContainerScope.() -> Unit,
) {
    val updatedOnResultFunc by rememberUpdatedState(onResult)

    val permissions: List<String> = requestScopes.map {
        when (it) {
            FacebookSignInRequestScope.Email -> "email"
            FacebookSignInRequestScope.PublicProfile -> "public_profile"
        }
    }

    val coroutineScope = rememberCoroutineScope()
    val uiContainerScope = remember {
        object : UiContainerScope {
            override fun onClick() {
                val loginManager = FBSDKLoginManager()

                val rootVCList = UIApplication.sharedApplication.connectedScenes.mapNotNull {
                    ((it as? UIWindowScene)?.windows?.firstOrNull() as? UIWindow)?.rootViewController
                }

                val rootVC = rootVCList.firstOrNull()
                if (rootVC == null) {
                    currentLogger.log("Root View Controller is null")
                    updatedOnResultFunc(Result.failure(IllegalStateException("Root View Controller is null")))
                    return
                }

                val nonce = generateNonce()
                val hashedNonce = sha256(nonce)

                loginManager.logInFromViewController(
                    rootVC,
                    FBSDKLoginConfiguration(
                        permissions = permissions,
                        tracking = FBSDKLoginTrackingLimited,
                        nonce = hashedNonce,
                    ),
                    completion = { result, error ->
                        if (error != null) {
                            currentLogger.log("Facebook Login failed with error: ${error.localizedDescription}")
                            updatedOnResultFunc(Result.failure(IllegalStateException(error.localizedDescription)))
                            return@logInFromViewController
                        }
                        if (result?.isCancelled() == true) {
                            updatedOnResultFunc(Result.failure(IllegalStateException("User cancelled the login process")))
                            return@logInFromViewController
                        }

                        coroutineScope.launch {
                            val idToken = result?.authenticationToken()?.tokenString()
                                ?: run {
                                    updatedOnResultFunc(Result.failure(IllegalStateException("No Facebook ID token")))
                                    return@launch
                                }

                            val facebookUid = fbUidFromIdToken(idToken)

                            val credential = OAuthProvider.credential(
                                providerId = "facebook.com",
                                idToken = idToken,
                                rawNonce = nonce
                            )

                            try {
                                val auth = Firebase.auth
                                val currentUser = auth.currentUser

                                // If already linked to the SAME FB account → success (no-op)
                                if (linkAccount && currentUser != null && !facebookUid.isNullOrEmpty()) {
                                    val linked =
                                        currentUser.providerData.firstOrNull { it.providerId == "facebook.com" }
                                    if (linked != null && linked.uid == facebookUid) {
                                        updatedOnResultFunc(
                                            Result.success(
                                                FacebookSignInResult(
                                                    user = currentUser,
                                                    credential = FacebookCredentialPayload.IdTokenWithNonce(
                                                        idToken = idToken,
                                                        nonce = nonce,
                                                    )
                                                )
                                            )
                                        )
                                        return@launch
                                    }
                                }

                                val firebaseAuthResult = if (linkAccount && currentUser != null) {
                                    currentLogger.log("Linking Facebook account with current firebase user: ${currentUser.uid}")
                                    currentUser.linkWithCredential(credential)
                                } else {
                                    currentLogger.log("Signing in with Facebook account on Firebase")
                                    auth.signInWithCredential(credential)
                                }

                                val user = firebaseAuthResult.user
                                if (user == null) {
                                    currentLogger.log("Firebase sign-in failed: Firebase user is null")
                                    updatedOnResultFunc(Result.failure(IllegalStateException("Firebase user is null")))
                                } else {
                                    currentLogger.log("Firebase sign-in successful")
                                    val result = FacebookSignInResult(
                                        user = user,
                                        credential = FacebookCredentialPayload.IdTokenWithNonce(
                                            idToken = idToken,
                                            nonce = nonce,
                                        ),
                                    )
                                    updatedOnResultFunc(Result.success(result))
                                }

                            } catch (e: Exception) {
                                if (e is CancellationException) throw e

                                val msg = (e.message ?: "")

                                when {
                                    // Provider already linked to THIS user → treat as success (no-op)
                                    msg.contains("User has already been linked to the given provider.") -> {
                                        val user = Firebase.auth.currentUser
                                        updatedOnResultFunc(
                                            Result.success(
                                                FacebookSignInResult(
                                                    user = user,
                                                    credential = FacebookCredentialPayload.IdTokenWithNonce(
                                                        idToken = result?.authenticationToken()
                                                            ?.tokenString().orEmpty(),
                                                        nonce = nonce
                                                    )
                                                )
                                            )
                                        )
                                    }

                                    // Credential belongs to ANOTHER Firebase user
                                    msg.contains("This credential is already associated with a different user account.") -> {
                                        if (linkAccount) {
                                            val signedIn =
                                                Firebase.auth.signInWithCredential(credential)
                                            updatedOnResultFunc(
                                                Result.success(
                                                    FacebookSignInResult(
                                                        user = signedIn.user,
                                                        credential = FacebookCredentialPayload.IdTokenWithNonce(
                                                            idToken = result?.authenticationToken()
                                                                ?.tokenString().orEmpty(),
                                                            nonce = nonce
                                                        )
                                                    )
                                                )
                                            )
                                        } else {
                                            updatedOnResultFunc(Result.failure(e))
                                        }
                                    }

                                    else -> {
                                        updatedOnResultFunc(Result.failure(e))
                                    }
                                }
                            }
                        }
                    }
                )
            }
        }
    }

    Box(modifier = modifier) { uiContainerScope.content() }
}

@OptIn(ExperimentalForeignApi::class, ExperimentalStdlibApi::class)
private fun sha256(input: String): String {
    val hashedData = UByteArray(CC_SHA256_DIGEST_LENGTH)
    val inputData = input.encodeToByteArray()
    inputData.usePinned {
        CC_SHA256(it.addressOf(0), inputData.size.convert(), hashedData.refTo(0))
    }
    return hashedData.toByteArray().toHexString(HexFormat.Default)
}

@OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)
private fun fbUidFromIdToken(idToken: String): String? {
    val parts = idToken.split('.')
    if (parts.size != 3) return null
    val payload = parts[1]
        .replace('-', '+')
        .replace('_', '/')
        .let { it + "=".repeat((4 - it.length % 4) % 4) }
    val json = kotlin.io.encoding.Base64.decode(payload).decodeToString()
    val m = """"sub"\s*:\s*"([^"]+)"""".toRegex().find(json)
    return m?.groupValues?.get(1)
}
