package com.psycheai.companion.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.psycheai.companion.contacts.ContactResolver
import com.psycheai.companion.notifications.PsycheNotificationListenerService
import com.psycheai.companion.security.FortressKeystoreManager
import com.psycheai.companion.security.SensitiveNotificationFilter
import com.psycheai.companion.storage.EncryptedOfflineQueue
import com.psycheai.companion.sync.CompanionSyncClient
import java.util.concurrent.Executors

/**
 * Jetpack Compose Companion UI enforcing:
 * - QR / 6-digit SAS pairing confirmation over TLSv1.3
 * - Android NotificationListenerService & READ_CONTACTS real permission triggers
 * - Allowlisted package & pre-persistence OTP filter telemetry
 * - Encrypted Offline Queue & Presence status + Panic Wipe
 * - Manual Analyzer calling Legion 5 Pro Neural AI with CLIPBOARD-ONLY draft copying
 *   (auto_send_permitted = false)
 */
class MainActivity : ComponentActivity() {

    companion object {
        const val REQUIRES_USER_REVIEW = true
        const val AUTO_SEND_PERMITTED = false
        const val DEFAULT_WINDOWS_GATEWAY = "https://10.7.155.45:8443"
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

private fun isNotificationAccessEnabled(context: Context): Boolean {
    val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners").orEmpty()
    val cn = ComponentName(context, PsycheNotificationListenerService::class.java)
    return flat.contains(cn.flattenToString()) || flat.contains(cn.flattenToShortString())
}

@Composable
fun PsycheCompanionScreen() {
    val context = LocalContext.current
    val scroll = rememberScrollState()
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    val ioExecutor = remember { Executors.newSingleThreadExecutor() }
    val keystoreManager = remember { FortressKeystoreManager() }
    val offlineQueue = remember { EncryptedOfflineQueue(context, keystoreManager) }

    val initialPairing = remember { keystoreManager.loadPairingState(context) }

    DisposableEffect(Unit) {
        onDispose { ioExecutor.shutdown() }
    }

    var windowsHost by remember {
        mutableStateOf(
            initialPairing.gatewayUrl.ifBlank { MainActivity.DEFAULT_WINDOWS_GATEWAY },
        )
    }
    var sasCodeInput by remember { mutableStateOf("") }
    var pendingHandshake by remember { mutableStateOf<CompanionSyncClient.PendingPairingHandshake?>(null) }
    var isPaired by remember { mutableStateOf(initialPairing.paired) }
    var pairingStatus by remember {
        mutableStateOf(
            if (initialPairing.paired) {
                "PAIRED with ${initialPairing.gatewayUrl} | Pin: ${initialPairing.windowsTlsSha256.take(16)}..."
            } else {
                "Not paired yet. Ensure PC Launch_PSYCHE_AI is running on ${MainActivity.DEFAULT_WINDOWS_GATEWAY}."
            },
        )
    }

    var contactsStatus by remember { mutableStateOf("Tap below to grant Contacts & sync aliases to Legion 5 Pro.") }
    var notifAccessGranted by remember { mutableStateOf(isNotificationAccessEnabled(context)) }
    var offlineQueueCount by remember { mutableIntStateOf(runCatching { offlineQueue.count() }.getOrDefault(0)) }

    var senderInput by remember { mutableStateOf("") }
    var manualMessageInput by remember { mutableStateOf("") }
    var cleanDraftForClipboard by remember { mutableStateOf("") }
    var draftOutput by remember {
        mutableStateOf("Manual review draft will appear here (clipboard copy only; auto_send_permitted=false).")
    }
    var clipboardFeedback by remember { mutableStateOf("") }
    var isBusy by remember { mutableStateOf(false) }

    fun syncContactsAsync() {
        val state = keystoreManager.loadPairingState(context)
        val identity = state.identity
        if (!state.paired || identity == null) {
            contactsStatus = "Pair with Windows PC first before syncing contacts."
            return
        }
        isBusy = true
        contactsStatus = "Reading Android contacts & syncing aliases over TLS 1.3..."
        ioExecutor.execute {
            runCatching {
                val resolver = ContactResolver(context.contentResolver, keystoreManager)
                val contacts = resolver.readDeviceContacts(limit = 200)
                if (contacts.isEmpty()) {
                    return@runCatching "No phone contacts found to sync."
                }
                val signedBatch = resolver.buildSignedContactSyncJson(
                    deviceId = identity.deviceId,
                    contacts = contacts,
                    ed25519PrivateKey = identity.ed25519PrivateKey,
                )
                val client = CompanionSyncClient.forGateway(
                    baseUrl = state.gatewayUrl,
                    pinnedWindowsSha256 = state.windowsTlsSha256,
                    keystoreManager = keystoreManager,
                )
                when (val res = client.postContactsSync(signedBatch)) {
                    is CompanionSyncClient.SyncResult.Delivered -> {
                        val mapped = res.payload.optJSONArray("resolved_mappings")?.length() ?: contacts.size
                        "Synced ${contacts.size} contacts ($mapped mappings resolved on PC)."
                    }
                    is CompanionSyncClient.SyncResult.VaultLockedHold ->
                        "Windows Vault is locked — unlock vault on PC and retry."
                    is CompanionSyncClient.SyncResult.HttpError ->
                        "Contact sync error (${res.statusCode}): ${res.body}"
                }
            }.onSuccess { msg ->
                mainHandler.post {
                    isBusy = false
                    contactsStatus = msg
                }
            }.onFailure { err ->
                mainHandler.post {
                    isBusy = false
                    contactsStatus = "Contact sync failed: ${err.message ?: err.javaClass.simpleName}"
                }
            }
        }
    }

    val contactsPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            syncContactsAsync()
        } else {
            contactsStatus = "READ_CONTACTS permission denied. Contact names will remain ambiguous."
        }
    }

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
                    "auto_send_permitted=${MainActivity.AUTO_SEND_PERMITTED} | TLS 1.3 Only",
                style = MaterialTheme.typography.bodySmall,
            )

            // 1. Cryptographic QR / SAS Pairing Card
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("1. Desktop Pairing (X25519 + Ed25519 + 6-Digit SAS)", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        value = windowsHost,
                        onValueChange = { windowsHost = it },
                        label = { Text("Windows Gateway Endpoint (HTTPS/TLS 1.3)") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = sasCodeInput,
                        onValueChange = { if (it.length <= 6) sasCodeInput = it },
                        label = { Text("6-Digit SAS Verification Code") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            enabled = !isBusy,
                            onClick = {
                                isBusy = true
                                pairingStatus = "Connecting over TLS 1.3 to $windowsHost..."
                                ioExecutor.execute {
                                    runCatching {
                                        val client = CompanionSyncClient.forGateway(
                                            baseUrl = windowsHost,
                                            pinnedWindowsSha256 = null,
                                            keystoreManager = keystoreManager,
                                        )
                                        client.beginPairingHandshake(context)
                                    }.onSuccess { handshake ->
                                        mainHandler.post {
                                            isBusy = false
                                            pendingHandshake = handshake
                                            sasCodeInput = handshake.sas6Digit
                                            pairingStatus = "SAS ${handshake.sas6Digit} | PC TLS Pin: ${handshake.windowsTlsSha256.take(16)}... Verify & tap Confirm."
                                        }
                                    }.onFailure { err ->
                                        mainHandler.post {
                                            isBusy = false
                                            pairingStatus = "Handshake failed: ${err.message ?: err.javaClass.simpleName}"
                                        }
                                    }
                                }
                            },
                        ) {
                            Text("Start Pairing")
                        }
                        OutlinedButton(
                            enabled = !isBusy,
                            onClick = {
                                val currentPending = pendingHandshake
                                if (currentPending == null) {
                                    pairingStatus = "Tap 'Start Pairing' first to perform X25519 key exchange."
                                    return@OutlinedButton
                                }
                                if (sasCodeInput.length != 6 || !sasCodeInput.all(Char::isDigit)) {
                                    pairingStatus = "Enter the 6-digit numeric SAS code."
                                    return@OutlinedButton
                                }
                                isBusy = true
                                pairingStatus = "Verifying Ed25519 + SAS ${sasCodeInput} with Legion 5 Pro..."
                                ioExecutor.execute {
                                    runCatching {
                                        val client = CompanionSyncClient.forGateway(
                                            baseUrl = currentPending.gatewayUrl,
                                            pinnedWindowsSha256 = currentPending.windowsTlsSha256,
                                            keystoreManager = keystoreManager,
                                        )
                                        client.completePairingHandshake(context, currentPending, sasCodeInput)
                                    }.onSuccess { res ->
                                        mainHandler.post {
                                            isBusy = false
                                            when (res) {
                                                is CompanionSyncClient.SyncResult.Delivered -> {
                                                    val st = res.payload.optString("status")
                                                    isPaired = (st == "PAIRED")
                                                    pairingStatus = "Pairing $st | Pin: ${currentPending.windowsTlsSha256.take(16)}..."
                                                    pendingHandshake = null
                                                }
                                                is CompanionSyncClient.SyncResult.VaultLockedHold ->
                                                    pairingStatus = "Windows Vault locked (${res.message}). Unlock vault on PC."
                                                is CompanionSyncClient.SyncResult.HttpError ->
                                                    pairingStatus = "Confirm rejected (${res.statusCode}): ${res.body}"
                                            }
                                        }
                                    }.onFailure { err ->
                                        mainHandler.post {
                                            isBusy = false
                                            pairingStatus = "Pairing error: ${err.message ?: err.javaClass.simpleName}"
                                        }
                                    }
                                }
                            },
                        ) {
                            Text("Confirm SAS Pairing")
                        }
                    }
                    Text(pairingStatus, style = MaterialTheme.typography.bodySmall)
                }
            }

            // 2. Notification Access, Contacts, Allowlist, OTP Filter & Encrypted Queue Status
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("2. Permissions, Capture & Encrypted Offline Queue", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Notification Access: ${if (notifAccessGranted) "GRANTED" else "NOT GRANTED"} | Paired: $isPaired",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        "Allowlisted packages (${SensitiveNotificationFilter.DEFAULT_ALLOWED_PACKAGES.size}): " +
                            SensitiveNotificationFilter.DEFAULT_ALLOWED_PACKAGES.joinToString(", "),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        "Captured: ${PsycheNotificationListenerService.capturedEventCounter.get()} | " +
                            "Synced: ${PsycheNotificationListenerService.deliveredEventCounter.get()} | " +
                            "OTP dropped: ${PsycheNotificationListenerService.droppedSensitiveCounter.get()} | " +
                            "Queue depth: $offlineQueueCount",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(PsycheNotificationListenerService.lastSyncStatus.get(), style = MaterialTheme.typography.bodySmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = {
                                notifAccessGranted = isNotificationAccessEnabled(context)
                                context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                            },
                        ) {
                            Text("Notification Settings")
                        }
                        OutlinedButton(
                            enabled = !isBusy,
                            onClick = {
                                val hasPerm = ContextCompat.checkSelfPermission(
                                    context,
                                    Manifest.permission.READ_CONTACTS,
                                ) == PackageManager.PERMISSION_GRANTED
                                if (hasPerm) {
                                    syncContactsAsync()
                                } else {
                                    contactsPermissionLauncher.launch(Manifest.permission.READ_CONTACTS)
                                }
                            },
                        ) {
                            Text("Sync Contacts")
                        }
                    }
                    Text(contactsStatus, style = MaterialTheme.typography.bodySmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            enabled = !isBusy,
                            onClick = {
                                val state = keystoreManager.loadPairingState(context)
                                val identity = state.identity
                                if (!state.paired || identity == null) {
                                    draftOutput = "Pair with Windows PC first to flush offline queue."
                                    return@Button
                                }
                                isBusy = true
                                ioExecutor.execute {
                                    runCatching {
                                        val client = CompanionSyncClient.forGateway(
                                            baseUrl = state.gatewayUrl,
                                            pinnedWindowsSha256 = state.windowsTlsSha256,
                                            keystoreManager = keystoreManager,
                                        )
                                        val acked = client.flushOfflineQueueDetailed(
                                            queue = offlineQueue,
                                            deviceId = identity.deviceId,
                                            ed25519PrivateKey = identity.ed25519PrivateKey,
                                        )
                                        acked.forEach { evId -> runCatching { client.requestSynthesisForEvent(evId) } }
                                        acked.size to offlineQueue.count()
                                    }.onSuccess { (flushedCount, remaining) ->
                                        mainHandler.post {
                                            isBusy = false
                                            offlineQueueCount = remaining
                                            notifAccessGranted = isNotificationAccessEnabled(context)
                                            PsycheNotificationListenerService.lastSyncStatus.set(
                                                "Manual flush: synced $flushedCount batch(es); $remaining remaining.",
                                            )
                                        }
                                    }.onFailure { err ->
                                        mainHandler.post {
                                            isBusy = false
                                            offlineQueueCount = runCatching { offlineQueue.count() }.getOrDefault(0)
                                            PsycheNotificationListenerService.lastSyncStatus.set(
                                                "Flush failed: ${err.message ?: err.javaClass.simpleName}",
                                            )
                                        }
                                    }
                                }
                            },
                        ) {
                            Text("Flush Queue Now")
                        }
                        OutlinedButton(
                            onClick = {
                                runCatching {
                                    offlineQueue.panicWipeQueue()
                                    keystoreManager.clearPairingState(context)
                                }
                                isPaired = false
                                offlineQueueCount = 0
                                pairingStatus = "Panic Wipe executed: queue & pairing state cleared."
                            },
                        ) {
                            Text("Panic Wipe Offline Queue")
                        }
                    }
                }
            }

            // 3. Manual Fallback Analyzer (PC Neural AI + Clipboard-Only Draft Review)
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
                            enabled = !isBusy,
                            onClick = {
                                val text = manualMessageInput.trim()
                                if (text.isEmpty()) {
                                    draftOutput = "Enter a message to analyze."
                                    return@Button
                                }
                                if (SensitiveNotificationFilter.isSensitiveOrOtpNotification(text)) {
                                    cleanDraftForClipboard = ""
                                    draftOutput = "BLOCKED_PRE_PERSISTENCE: Sensitive OTP/banking text rejected."
                                    return@Button
                                }
                                val sender = senderInput.trim().ifBlank { "Manual Contact" }
                                val state = keystoreManager.loadPairingState(context)
                                val identity = state.identity
                                if (!state.paired || identity == null) {
                                    val fallbackDraft = "Got it, let us confirm the details shortly."
                                    cleanDraftForClipboard = fallbackDraft
                                    draftOutput = "Offline fallback draft for $sender (not paired to PC yet):\n$fallbackDraft"
                                    return@Button
                                }
                                isBusy = true
                                draftOutput = "Analyzing on Legion 5 Pro Neural AI & Memory Vault..."
                                ioExecutor.execute {
                                    runCatching {
                                        val client = CompanionSyncClient.forGateway(
                                            baseUrl = state.gatewayUrl,
                                            pinnedWindowsSha256 = state.windowsTlsSha256,
                                            keystoreManager = keystoreManager,
                                        )
                                        client.ingestSingleMessageAndSynthesize(
                                            deviceId = identity.deviceId,
                                            ed25519PrivateKey = identity.ed25519PrivateKey,
                                            senderName = sender,
                                            messageText = text,
                                        )
                                    }.onSuccess { res ->
                                        mainHandler.post {
                                            isBusy = false
                                            when (res) {
                                                is CompanionSyncClient.SyncResult.Delivered -> {
                                                    val pkt = res.payload
                                                    val goal = pkt.optJSONObject("goal_aware_recommendations")
                                                    val candidates = goal?.optJSONArray("reply_candidates")
                                                    val top = candidates?.optJSONObject(0)
                                                    val topDraft = top?.optString("draft_text").orEmpty()
                                                        .ifBlank { "Thanks for letting me know — let us follow up soon." }
                                                    val rationale = top?.optString("strategy_label").orEmpty()
                                                    val uncertainty = pkt.optJSONObject("uncertainty")?.optString("epistemic_label").orEmpty()
                                                    val engine = pkt.optJSONObject("local_core_trace")?.optString("engine_used").orEmpty()
                                                    cleanDraftForClipboard = topDraft
                                                    draftOutput = buildString {
                                                        append("Suggested Draft ($rationale | $uncertainty | $engine):\n")
                                                        append(topDraft)
                                                        if (candidates != null && candidates.length() > 1) {
                                                            append("\n\nAlt: ")
                                                            append(candidates.optJSONObject(1)?.optString("draft_text").orEmpty())
                                                        }
                                                    }
                                                }
                                                is CompanionSyncClient.SyncResult.VaultLockedHold -> {
                                                    cleanDraftForClipboard = ""
                                                    draftOutput = "Windows Vault locked — unlock on Legion 5 Pro first."
                                                }
                                                is CompanionSyncClient.SyncResult.HttpError -> {
                                                    cleanDraftForClipboard = ""
                                                    draftOutput = "Gateway error (${res.statusCode}): ${res.body}"
                                                }
                                            }
                                        }
                                    }.onFailure { err ->
                                        mainHandler.post {
                                            isBusy = false
                                            val fallbackDraft = "Got it, let us confirm the details shortly."
                                            cleanDraftForClipboard = fallbackDraft
                                            draftOutput = "Offline fallback (${err.message ?: "PC unreachable"}):\n$fallbackDraft"
                                        }
                                    }
                                }
                            },
                        ) {
                            Text("Analyze on PC")
                        }
                        OutlinedButton(
                            onClick = {
                                val textToCopy = cleanDraftForClipboard.ifBlank { draftOutput }
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("PSYCHE Draft", textToCopy))
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
