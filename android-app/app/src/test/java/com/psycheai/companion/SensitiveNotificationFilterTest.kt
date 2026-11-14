package com.psycheai.companion

import com.psycheai.companion.notifications.PsycheNotificationListenerService
import com.psycheai.companion.security.SensitiveNotificationFilter
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SensitiveNotificationFilterTest {

    @Test
    fun dropsOtpAndBankingMessagesPrePersistence() {
        assertTrue(SensitiveNotificationFilter.isSensitiveOrOtpNotification("482910 is your OTP for HDFC UPI login"))
        assertTrue(SensitiveNotificationFilter.isSensitiveOrOtpNotification("A/c XXXX1234 debited by Rs 5000"))
        assertFalse(SensitiveNotificationFilter.isSensitiveOrOtpNotification("Bro meeting 8 PM-nu shift cheyyamo?", "com.whatsapp"))
    }

    @Test
    fun enforcesZeroAutoSendAndPackageAllowlist() {
        assertTrue(PsycheNotificationListenerService.REQUIRES_USER_REVIEW)
        assertFalse(PsycheNotificationListenerService.AUTO_SEND_PERMITTED)
        assertTrue(SensitiveNotificationFilter.isPackageAllowed("com.whatsapp"))
        assertFalse(SensitiveNotificationFilter.isPackageAllowed("com.google.android.apps.authenticator2"))
    }
}
