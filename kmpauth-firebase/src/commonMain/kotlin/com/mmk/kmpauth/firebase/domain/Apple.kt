package com.mmk.kmpauth.firebase.domain

import dev.gitlive.firebase.auth.FirebaseUser

public data class AppleSignInResult(
    val user: FirebaseUser?,
    val nonce: String,
)
