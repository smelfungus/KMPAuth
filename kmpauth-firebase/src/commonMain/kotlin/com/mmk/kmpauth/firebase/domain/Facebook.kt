package com.mmk.kmpauth.firebase.domain

import dev.gitlive.firebase.auth.FirebaseUser

public sealed class FacebookCredentialPayload {

    public data class AccessToken(val token: String) : FacebookCredentialPayload()

    public data class IdTokenWithNonce(
        val idToken: String,
        val nonce: String,
    ) : FacebookCredentialPayload()
}

public data class FacebookSignInResult(
    val user: FirebaseUser?,
    val credential: FacebookCredentialPayload,
)
