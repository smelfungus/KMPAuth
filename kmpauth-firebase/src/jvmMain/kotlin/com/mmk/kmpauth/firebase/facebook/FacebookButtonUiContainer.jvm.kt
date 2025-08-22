package com.mmk.kmpauth.firebase.facebook

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.mmk.kmpauth.core.KMPAuthInternalApi
import com.mmk.kmpauth.core.UiContainerScope
import com.mmk.kmpauth.core.logger.currentLogger
import com.mmk.kmpauth.firebase.domain.FacebookSignInResult

@OptIn(KMPAuthInternalApi::class)
@Composable
public actual fun FacebookButtonUiContainer(
    modifier: Modifier,
    requestScopes: List<FacebookSignInRequestScope>,
    onResult: (Result<FacebookSignInResult>) -> Unit,
    linkAccount: Boolean,
    content: @Composable (UiContainerScope.() -> Unit)
) {
    currentLogger.log("Facebook Login is not supported on JVM")
}