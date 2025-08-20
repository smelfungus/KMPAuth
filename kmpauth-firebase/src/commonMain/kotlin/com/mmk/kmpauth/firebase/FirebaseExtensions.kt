package com.mmk.kmpauth.firebase

import com.mmk.kmpauth.core.FirebaseAuthErrorType
import dev.gitlive.firebase.auth.FirebaseAuthException

public expect fun getAuthErrorType(e: FirebaseAuthException): FirebaseAuthErrorType
