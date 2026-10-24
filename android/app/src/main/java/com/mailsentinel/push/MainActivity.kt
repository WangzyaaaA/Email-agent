package com.mailsentinel.push

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

class MainActivity : AppCompatActivity() {
    private lateinit var statusView: TextView
    private lateinit var pairingInput: EditText
    private lateinit var previewSwitch: SwitchCompat

    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        result.contents?.let(::consumePairing)
    }
    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        refreshStatus()
        WorkScheduling.sync(this)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(buildUi())
        handleViewedMessage(intent)
        refreshStatus()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleViewedMessage(intent)
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
        if (CredentialStore(this).load() != null) WorkScheduling.sync(this)
    }

    private fun buildUi(): View {
        val density = resources.displayMetrics.density
        fun dp(value: Int) = (value * density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(28), dp(20), dp(28))
        }
        root.addView(TextView(this).apply { text = "Mail Sentinel"; textSize = 28f })
        root.addView(TextView(this).apply {
            text = "端到端加密 Android 推送。App 不能发送、删除、移动邮件，也不能远程修改 NAS。"
            textSize = 15f
            setPadding(0, dp(8), 0, dp(18))
        })
        statusView = TextView(this).apply { textSize = 16f; setPadding(0, dp(8), 0, dp(16)) }
        root.addView(statusView)

        root.addView(Button(this).apply {
            text = "扫描 NAS 配对二维码"
            setOnClickListener {
                scanLauncher.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("扫描 Mail Sentinel 一次性二维码").setBeepEnabled(false))
            }
        })
        pairingInput = EditText(this).apply {
            hint = "或粘贴一次性配对配置"
            minLines = 3
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            setSaveEnabled(false)
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        }
        root.addView(pairingInput)
        root.addView(Button(this).apply {
            text = "导入粘贴的配对配置"
            setOnClickListener { consumePairing(pairingInput.text.toString()) }
        })

        root.addView(TextView(this).apply {
            text = "通知权限用于显示验证码、安全告警和重要邮件。拒绝后，App 仍可安全保存已收到的密文，但不会显示通知。"
            setPadding(0, dp(22), 0, dp(8))
        })
        root.addView(Button(this).apply {
            text = if (Build.VERSION.SDK_INT >= 33) "请求通知权限" else "查看通知设置"
            setOnClickListener {
                if (Build.VERSION.SDK_INT >= 33) notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                else openNotificationSettings()
            }
        })
        root.addView(Button(this).apply {
            text = "打开系统通知设置"
            setOnClickListener { openNotificationSettings() }
        })

        previewSwitch = SwitchCompat(this).apply {
            text = "允许锁屏预览敏感内容"
            isChecked = CredentialStore(this@MainActivity).sensitivePreviewEnabled()
            setOnCheckedChangeListener { _, enabled -> CredentialStore(this@MainActivity).setSensitivePreviewEnabled(enabled) }
        }
        root.addView(previewSwitch)
        root.addView(TextView(this).apply {
            text = "默认关闭。开启后，验证码可能进入通知历史，并可能被截图、肩窥或辅助功能读取。"
            textSize = 13f
            setPadding(0, 0, 0, dp(18))
        })

        root.addView(Button(this).apply {
            text = "清除本机配对和通知密文"
            setOnClickListener {
                CredentialStore(this@MainActivity).clear()
                MessageStore(this@MainActivity).clearAll()
                refreshStatus("本机数据已清除；请同时在 NAS 管理页吊销旧设备。")
            }
        })
        return ScrollView(this).apply { addView(root) }
    }

    private fun consumePairing(raw: String) {
        try {
            val pairing = PairingConfig.parse(raw.trim())
            CredentialStore(this).savePairing(pairing)
            pairingInput.text.clear()
            if (FirebaseApp.getApps(this).isEmpty()) {
                refreshStatus("配对已安全保存，但 APK 尚未配置 Firebase 项目标识。")
                return
            }
            FirebaseMessaging.getInstance().register().addOnCompleteListener { task ->
                if (task.isSuccessful) {
                    refreshStatus("配对已保存，正在等待 FCM 登记回调并向网关登记设备。")
                } else {
                    refreshStatus("配对已保存，FCM 登记暂不可用，将在网络恢复后重试。")
                    WorkScheduling.register(this)
                }
            }
        } catch (_: Exception) {
            pairingInput.text.clear()
            refreshStatus("配对配置无效、已过期或不符合 HTTPS 安全要求。")
        }
    }

    private fun refreshStatus(message: String? = null) {
        val state = CredentialStore(this).load()
        val paired = state != null
        val permission = NotificationHelper.notificationsEnabled(this)
        val firebase = FirebaseApp.getApps(this).isNotEmpty()
        statusView.text = message ?: buildString {
            append(if (paired) "设备已配对" else "设备未配对")
            append(" · ")
            append(if (permission) "通知权限可用" else "通知权限受限")
            append(" · ")
            append(if (firebase) "Firebase 已配置" else "Firebase 未配置")
            if (state != null) {
                append("\n")
                append(if (state.registered) "网关登记：已完成" else "网关登记：等待完成，暂不拉取通知")
                state.lastError?.let { append("\n最近网关响应：").append(it) }
            }
        }
    }

    private fun openNotificationSettings() {
        startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
    }

    private fun handleViewedMessage(intent: Intent) {
        intent.getStringExtra("message_id")?.let {
            MessageStore(this).markViewed(it)
            intent.removeExtra("message_id")
        }
    }
}
