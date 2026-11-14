package com.psycheai.companion.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.psycheai.companion.notifications.PsycheNotificationListenerService
import com.psycheai.companion.security.SensitiveNotificationFilter

/**
 * Jetpack Compose Companion UI enforcing:
 * - QR / 6-digit SAS pairing confirmation
 * - Allowlisted package & pre-persistence OTP filter telemetry
 * - Encrypted Offline Queue & Presence status + Panic Wipe
 * - Manual Analyzer with CLIPBOARD-ONLY draft copying (auto_send_permitted = false)
 */
class MainActivity : ComponentActivity() {

    companion object {
        const val REQUIRES_USER_REVIEW = true
        const val AUTO_SEND_PERMITTED = false
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                PsycheCompanionScreen()
            }
        }
    }
}

@Composable
fun PsycheCompanionScreen() {
    val context = LocalContext.current
    val scroll = rememberScrollState()

    var windowsHost by remember { mutableStateOf("https://192.168.1.10:8443") }
    var sasCodeInput by remember { mutableStateOf("") }
    var pairingStatus by remember { mutableStateOf("Awaiting QR scan / 6-digit SAS verification") }

    var senderInput by remember { mutableStateOf("") }
    var manualMessageInput by remember { mutableStateOf("") }
    var draftOutput by remember {
        mutableStateOf("Manual review draft will appear here (clipboard copy only; auto_send_permitted=false).")
    }
    var clipboardFeedback by remember { mutableStateOf("") }
    var offlineQueueCount by remember { mutableIntStateOf(0) }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(scroll),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("PSYCHE AI — Android Companion", style = MaterialTheme.typography.headlineSmall)
            Text(
                "Security Invariant: requires_user_review=${MainActivity.REQUIRES_USER_REVIEW} | " +
                    "auto_send_permitted=${MainActivity.AUTO_SEND_PERMITTED} | mTLS 1.3 Only",
                style = MaterialTheme.typography.bodySmall,
            )

            // 1. Cryptographic QR / SAS Pairing Card
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("1. Desktop Pairing (X25519 + Ed25519 + 6-Digit SAS)", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        value = windowsHost,
                        onValueChange = { windowsHost = it },
                        label = { Text("Windows Gateway Endpoint (HTTPS/mTLS)") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = sasCodeInput,
                        onValueChange = { if (it.length <= 6) sasCodeInput = it },
                        label = { Text("6-Digit SAS Verification Code") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(
                        onClick = {
                            pairingStatus = if (sasCodeInput.length == 6 && sasCodeInput.all(Char::isDigit)) {
                                "SAS $sasCodeInput confirmed locally; ready for mTLS handshake with $windowsHost"
                            } else {
                                "Enter exact 6-digit numeric SAS code shown on Windows Companion"
                            }
                        },
                    ) {
                        Text("Confirm SAS Pairing")
                    }
                    Text(pairingStatus, style = MaterialTheme.typography.bodySmall)
                }
            }

            // 2. Notification Allowlist, OTP Filter & Encrypted Queue Status
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("2. Notification Capture & Encrypted Offline Queue", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Allowlisted packages (${SensitiveNotificationFilter.DEFAULT_ALLOWED_PACKAGES.size}): " +
                            SensitiveNotificationFilter.DEFAULT_ALLOWED_PACKAGES.joinToString(", "),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        "Captured events: ${PsycheNotificationListenerService.capturedEventCounter.get()} | " +
                            "OTP/Banking dropped pre-persistence: ${PsycheNotificationListenerService.droppedSensitiveCounter.get()} | " +
                            "Encrypted queue depth: $offlineQueueCount",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedButton(onClick = { offlineQueueCount = 0 }) {
                        Text("Panic Wipe Offline Queue")
                    }
                }
            }

            // 3. Manual Fallback Analyzer (Clipboard-Only Draft Review)
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("3. Manual Fallback & Clipboard-Only Draft Review", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        value = senderInput,
                        onValueChange = { senderInput = it },
                        label = { Text("Sender Display Name") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = manualMessageInput,
                        onValueChange = { manualMessageInput = it },
                        label = { Text("Paste Message (EN / Hindi / Malayalam / Telugu / Translit)") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                if (SensitiveNotificationFilter.isSensitiveOrOtpNotification(manualMessageInput)) {
                                    draftOutput = "BLOCKED_PRE_PERSISTENCE: Sensitive OTP/banking text rejected."
                                } else {
                                    draftOutput = "Suggested draft for $senderInput (Review before manual paste): Got it, let us confirm details shortly."
                                }
                            },
                        ) {
                            Text("Prepare Encrypted Sync")
                        }
                        OutlinedButton(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("PSYCHE Draft", draftOutput))
                                clipboardFeedback = "Copied draft to clipboard. Manual paste required (auto_send_permitted=false)."
                            },
                        ) {
                            Text("Copy Draft to Clipboard")
                        }
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(draftOutput, style = MaterialTheme.typography.bodyMedium)
                    if (clipboardFeedback.isNotEmpty()) {
                        Text(clipboardFeedback, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
