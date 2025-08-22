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
import com.mmk.kmpauth.core.FirebaseAuthErrorType
import com.mmk.kmpauth.core.KMPAuthError
import com.mmk.kmpauth.core.KMPAuthErrorType
import com.mmk.kmpauth.core.KMPAuthInternalApi
import com.mmk.kmpauth.core.UiContainerScope
import com.mmk.kmpauth.core.logger.currentLogger
import com.mmk.kmpauth.firebase.domain.FacebookCredentialPayload
import com.mmk.kmpauth.firebase.domain.FacebookSignInResult
import com.mmk.kmpauth.firebase.getAuthErrorType
import dev.gitlive.firebase.Firebase
import dev.gitlive.firebase.auth.FirebaseAuthException
import dev.gitlive.firebase.auth.FirebaseUser
import dev.gitlive.firebase.auth.OAuthProvider
import dev.gitlive.firebase.auth.auth
import io.ktor.util.generateNonce
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.UIKit.UIApplication
import platform.UIKit.UIViewController
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
    onResult: (Result<FacebookSignInResult>) -> Unit,
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

                val rootVC = getRootViewController()
                if (rootVC == null) {
                    currentLogger.log("Root View Controller is null")
                    updatedOnResultFunc(Result.failure(KMPAuthError(type = KMPAuthErrorType.UI)))
                    return
                }

                loginManager.logOut()

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
                            updatedOnResultFunc(
                                Result.failure(
                                    KMPAuthError(
                                        type = KMPAuthErrorType.UNKNOWN,
                                        message = error.localizedDescription,
                                    )
                                )
                            )
                            return@logInFromViewController
                        }
                        if (result?.isCancelled() == true) {
                            updatedOnResultFunc(Result.failure(KMPAuthError(type = KMPAuthErrorType.USER_CANCELLED)))
                            return@logInFromViewController
                        }

                        coroutineScope.launch {
                            val idToken = result?.authenticationToken()?.tokenString()
                                ?: run {
                                    updatedOnResultFunc(Result.failure(KMPAuthError(type = KMPAuthErrorType.NO_ID_TOKEN)))
                                    return@launch
                                }

                            val facebookUid = extractFacebookUserId(idToken)

                            val credential = OAuthProvider.credential(
                                providerId = "facebook.com",
                                idToken = idToken,
                                rawNonce = nonce,
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
                                                    ),
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
                                    updatedOnResultFunc(Result.failure(KMPAuthError(type = KMPAuthErrorType.NO_FIREBASE_USER)))
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

                                when (e) {
                                    is FirebaseAuthException -> {
                                        val errorType = getAuthErrorType(e)
                                        when (errorType) {
                                            FirebaseAuthErrorType.UNKNOWN -> {
                                                currentLogger.log("Facebook sign-in failed with exception: $e")
                                                updatedOnResultFunc(
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
                                                updatedOnResultFunc(
                                                    result
                                                        .authenticationToken()
                                                        ?.tokenString()
                                                        ?.let {
                                                            Result.success(
                                                                FacebookSignInResult(
                                                                    user = user,
                                                                    credential = FacebookCredentialPayload.IdTokenWithNonce(
                                                                        idToken = it,
                                                                        nonce = nonce,
                                                                    ),
                                                                )
                                                            )
                                                        }
                                                        ?: Result.failure(
                                                            KMPAuthError(
                                                                type = KMPAuthErrorType.NO_ID_TOKEN,
                                                            )
                                                        )
                                                )
                                            }

                                            FirebaseAuthErrorType.CREDENTIAL_ALREADY_IN_USE -> {
                                                // Credential belongs to ANOTHER Firebase user
                                                if (linkAccount) {
                                                    val signedIn =
                                                        Firebase.auth.signInWithCredential(
                                                            credential
                                                        )
                                                    updatedOnResultFunc(
                                                        Result.success(
                                                            result
                                                                .authenticationToken()
                                                                ?.tokenString()
                                                                ?.let {
                                                                    FacebookSignInResult(
                                                                        user = signedIn.user,
                                                                        credential = FacebookCredentialPayload.IdTokenWithNonce(
                                                                            idToken = it,
                                                                            nonce = nonce,
                                                                        ),
                                                                    )
                                                                }
                                                                ?: Result.failure(
                                                                    KMPAuthError(
                                                                        type = KMPAuthErrorType.NO_ID_TOKEN,
                                                                    )
                                                                )
                                                        )
                                                    )
                                                } else {
                                                    updatedOnResultFunc(
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
                                                updatedOnResultFunc(
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
                                        currentLogger.log("Facebook sign-in failed with exception: $e")
                                        updatedOnResultFunc(
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
                )
            }
        }
    }

    Box(modifier = modifier) { uiContainerScope.content() }
}

/**
 * Generates SHA256 hash of the input string.
 * Used for hashing the nonce before sending to Facebook.
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalStdlibApi::class)
private fun sha256(input: String): String {
    val hashedData = UByteArray(CC_SHA256_DIGEST_LENGTH)
    val inputData = input.encodeToByteArray()

    inputData.usePinned { inputPinned ->
        hashedData.usePinned { hashedPinned ->
            CC_SHA256(
                inputPinned.addressOf(0),
                inputData.size.convert(),
                hashedPinned.addressOf(0),
            )
        }
    }

    return hashedData.toByteArray().toHexString(HexFormat.Default)
}

private fun getRootViewController(): UIViewController? {
    // Get the first active window scene's key window
    // val activeWindow = UIApplication.sharedApplication.connectedScenes
    //     .mapNotNull { it as? UIWindowScene }
    //     .filter { it.activationState == UISceneActivationStateForegroundActive }
    //     .flatMap { it.windows.toList() }
    //     .firstOrNull { it.isKeyWindow() }

    // Return the root view controller, with iOS 12 fallback
    // return activeWindow?.rootViewController
    //     ?: UIApplication.sharedApplication.keyWindow?.rootViewController

    return UIApplication.sharedApplication.connectedScenes.firstNotNullOfOrNull {
        ((it as? UIWindowScene)?.windows?.firstOrNull() as? UIWindow)?.rootViewController
    }
}

/**
 * Robustly extracts the Facebook User ID (sub claim) from a JWT ID token.
 * Uses proper JSON parsing instead of regex for reliability.
 *
 * @param idToken The JWT ID token from Facebook
 * @return The Facebook User ID or null if extraction fails
 */
@OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class, KMPAuthInternalApi::class)
private fun extractFacebookUserId(idToken: String): String? {
    try {
        // JWT consists of three parts: header.payload.signature
        val parts = idToken.split('.')
        if (parts.size != 3) {
            currentLogger.log("Invalid JWT format: expected 3 parts, got ${parts.size}")
            return null
        }

        // Extract and decode the payload (second part)
        val payload = parts[1]

        // JWT uses base64url encoding, need to convert to standard base64
        val base64Payload = payload
            .replace('-', '+')
            .replace('_', '/')

        // Add padding if necessary (base64 requires padding to be multiple of 4)
        val paddedPayload = when (base64Payload.length % 4) {
            2 -> "$base64Payload=="
            3 -> "$base64Payload="
            else -> base64Payload
        }

        // Decode base64 to get JSON string
        val jsonBytes = kotlin.io.encoding.Base64.decode(paddedPayload)
        val jsonString = jsonBytes.decodeToString()

        // Parse JSON and extract 'sub' claim
        val jsonElement = Json.parseToJsonElement(jsonString)
        val jsonObject = jsonElement.jsonObject

        // Extract the 'sub' claim (Facebook User ID)
        val sub = jsonObject["sub"]?.jsonPrimitive?.contentOrNull

        if (sub == null) {
            currentLogger.log("No 'sub' claim found in JWT payload")
        } else {
            currentLogger.log("Successfully extracted Facebook UID: $sub")

            // Optional: Log other useful claims for debugging
            // val aud = jsonObject["aud"]?.jsonPrimitive?.contentOrNull
            // val iss = jsonObject["iss"]?.jsonPrimitive?.contentOrNull
            // val exp = jsonObject["exp"]?.jsonPrimitive?.longOrNull
            // currentLogger.log("JWT Claims - aud: $aud, iss: $iss, exp: $exp")
        }

        return sub

    } catch (e: Exception) {
        currentLogger.log("Failed to extract Facebook UID from JWT: ${e.message}")
        return null
    }
}
