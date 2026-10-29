
package FRAMES;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public class PhoneAnalyzer {

    public static class AnalysisResult {
        public int riskScore;
        public String classification;
        public ArrayList<String> reasons;

        public AnalysisResult(
                int riskScore,
                String classification,
                ArrayList<String> reasons) {

            this.riskScore = riskScore;
            this.classification = classification;
            this.reasons = reasons;
        }
    }

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)(https?://|www\\.)\\S+");

    private static final Pattern OTP_REQUEST_PATTERN = Pattern.compile(
            "(?i)\\b(?:share|send|tell|reveal|provide|forward)"
            + "\\s+(?:me\\s+)?(?:your\\s+)?"
            + "(?:otp|one[- ]time password|verification code)\\b");

    private static final Pattern PASSWORD_REQUEST_PATTERN = Pattern.compile(
            "(?i)\\b(?:share|send|provide|enter|reveal)"
            + "\\s+(?:your\\s+)?(?:password|pin|cvv|card details|"
            + "bank details|login credentials)\\b");

    private static final String[] URGENCY_PHRASES = {
            "urgent", "immediately", "act now",
            "within 24 hours", "within 2 hours",
            "final warning", "last warning",
            "account will be blocked", "account blocked",
            "account suspended", "account will be suspended",
            "sim will be blocked", "electricity will be disconnected",
            "legal action", "police will arrest you"
    };

    private static final String[] BANK_KYC_PHRASES = {
            "kyc expired", "update your kyc",
            "complete your kyc", "kyc verification",
            "verify your bank account",
            "bank account blocked", "bank account suspended",
            "update pan details", "account verification"
    };

    private static final String[] PAYMENT_PHRASES = {
            "send money", "transfer money", "pay now",
            "processing fee", "registration fee",
            "claim fee", "release fee",
            "refundable deposit", "upi payment",
            "approve the payment", "scan and pay",
            "pay to receive", "pay to unlock"
    };

    private static final String[] PRIZE_PHRASES = {
            "you have won", "you won",
            "claim your prize", "lucky winner",
            "lottery winner", "cash prize",
            "free gift", "claim your reward",
            "guaranteed reward"
    };

    private static final String[] REMOTE_ACCESS_PHRASES = {
            "install anydesk", "install teamviewer",
            "install remote access", "download this apk",
            "install this app", "share your screen",
            "enable screen sharing", "give remote access"
    };

    private static final String[] IMPERSONATION_PHRASES = {
            "i am calling from your bank",
            "bank customer support",
            "customer care executive",
            "government officer",
            "police department",
            "income tax department",
            "customs department",
            "courier department",
            "your account manager"
    };

    private static final String[] SECRECY_PHRASES = {
            "do not tell anyone",
            "don't tell anyone",
            "keep this confidential",
            "do not contact your bank",
            "do not tell your family",
            "keep this secret"
    };

    private static final String[] SAFE_WARNING_PHRASES = {
            "never share your otp",
            "do not share your otp",
            "don't share your otp",
            "never share your password",
            "do not share your password",
            "don't share your password",
            "never share your pin",
            "do not share your pin",
            "don't share your pin",
            "fraud awareness",
            "scam awareness",
            "security awareness",
            "example of a scam message"
    };

    public static AnalysisResult analyze(
            String phone, String context) {

        Set<String> reasons = new LinkedHashSet<>();
        int risk = 0;

        if (phone == null || phone.trim().isEmpty()) {
            ArrayList<String> invalidReasons = new ArrayList<>();
            invalidReasons.add("Please enter a phone number.");

            return new AnalysisResult(
                    0, "INVALID INPUT", invalidReasons);
        }

        // Allow common formatting characters, but reject letters.
        String cleaned = phone.trim();

        if (!cleaned.matches("[+0-9().\\-\\s]+")) {
            reasons.add(
                    "The phone number contains unexpected characters.");

            return new AnalysisResult(
                    0, "INVALID FORMAT - UNABLE TO ASSESS",
                    new ArrayList<>(reasons));
        }

        String digits = cleaned.replaceAll("\\D", "");

        // Accept Indian numbers with country code +91.
        if (digits.startsWith("91") && digits.length() == 12) {
            digits = digits.substring(2);
        }

        // Accept a leading zero before a 10-digit Indian number.
        if (digits.startsWith("0") && digits.length() == 11) {
            digits = digits.substring(1);
        }

        if (digits.length() != 10
                || digits.charAt(0) < '6'
                || digits.charAt(0) > '9') {

            reasons.add(
                    "The number does not match the expected "
                    + "10-digit Indian mobile format.");

            reasons.add(
                    "This scanner cannot assess the number using "
                    + "its current Indian mobile-number rules.");

            return new AnalysisResult(
                    0,
                    "INVALID FORMAT - UNABLE TO ASSESS",
                    new ArrayList<>(reasons));
        }

        String text = context == null
                ? ""
                : context.toLowerCase(Locale.ROOT)
                        .replace('\u2019', '\'')
                        .replace('\u2018', '\'');

        // A phone number alone does not establish fraud.
        reasons.add(
                "The number format is consistent with a typical "
                + "Indian mobile number; this does not verify its owner.");

        if (text.trim().isEmpty()) {
            reasons.add(
                    "No call or message context was supplied, so "
                    + "fraud-related behaviour cannot be assessed.");

            return new AnalysisResult(
                    0,
                    "LOW RISK - INSUFFICIENT CONTEXT",
                    new ArrayList<>(reasons));
        }

        // Avoid treating educational warnings as actual scam attempts.
        for (String phrase : SAFE_WARNING_PHRASES) {
            if (text.contains(phrase)) {
                reasons.clear();
                reasons.add(
                        "The supplied context appears to contain "
                        + "security advice or fraud-awareness content.");

                return new AnalysisResult(
                        0,
                        "LOW RISK - POSSIBLE AWARENESS CONTENT",
                        new ArrayList<>(reasons));
            }
        }

        // 1. OTP theft.
        boolean otpRequest =
                OTP_REQUEST_PATTERN.matcher(text).find();

        if (otpRequest) {
            risk += 40;
            reasons.add(
                    "The supplied context appears to request an OTP "
                    + "or verification code.");
        }

        // 2. Password, PIN, CVV, or banking credentials.
        if (PASSWORD_REQUEST_PATTERN.matcher(text).find()) {
            risk += 35;
            reasons.add(
                    "The context appears to request sensitive "
                    + "credentials or banking information.");
        }

        // 3. Urgency and pressure.
        boolean urgent = containsAny(text, URGENCY_PHRASES);

        if (urgent) {
            risk += 15;
            reasons.add(
                    "Urgent deadlines, threats, or pressure tactics "
                    + "were detected.");
        }

        // 4. Banking and KYC claims.
        boolean bankKyc = containsAny(text, BANK_KYC_PHRASES);

        if (bankKyc) {
            risk += 20;
            reasons.add(
                    "Banking, KYC, or account-verification claims "
                    + "were detected.");
        }

        // 5. Payment requests.
        boolean payment = containsAny(text, PAYMENT_PHRASES);

        if (payment) {
            risk += 25;
            reasons.add(
                    "The context contains a payment, transfer, "
                    + "fee, or payment-approval request.");
        }

        // 6. Unexpected prizes and rewards.
        boolean prize = containsAny(text, PRIZE_PHRASES);

        if (prize) {
            risk += 25;
            reasons.add(
                    "An unexpected prize, lottery win, or reward "
                    + "is mentioned.");
        }

        // 7. Remote-access requests.
        boolean remoteAccess =
                containsAny(text, REMOTE_ACCESS_PHRASES);

        if (remoteAccess) {
            risk += 30;
            reasons.add(
                    "The context asks for remote access, screen sharing, "
                    + "or installation of an application.");
        }

        // 8. Impersonation claims.
        boolean impersonation =
                containsAny(text, IMPERSONATION_PHRASES);

        if (impersonation) {
            risk += 15;
            reasons.add(
                    "The sender claims to represent an organization "
                    + "or authority. The claim is unverified.");
        }

        // 9. Suspicious secrecy instructions.
        if (containsAny(text, SECRECY_PHRASES)) {
            risk += 15;
            reasons.add(
                    "The context discourages disclosure or independent "
                    + "verification.");
        }

        // 10. Links in the supplied context.
        boolean hasUrl = URL_PATTERN.matcher(text).find();

        if (hasUrl) {
            risk += 10;
            reasons.add(
                    "The supplied context contains a web link. "
                    + "Its safety has not been verified.");
        }

        // 11. Combined-indicator bonus.
        int indicators = 0;

        if (otpRequest) indicators++;
        if (urgent) indicators++;
        if (bankKyc) indicators++;
        if (payment) indicators++;
        if (prize) indicators++;
        if (remoteAccess) indicators++;
        if (impersonation) indicators++;
        if (hasUrl) indicators++;

        if (indicators >= 3) {
            risk += 10;
            reasons.add(
                    "Multiple independent warning signs appear together, "
                    + "increasing concern.");
        }

        risk = Math.min(risk, 100);

        String classification;

        if (risk >= 60) {
            classification = "HIGH RISK - POSSIBLE SCAM";
        } else if (risk >= 25) {
            classification = "SUSPICIOUS - REVIEW CAREFULLY";
        } else {
            classification = "LOW RISK - NO MAJOR FLAGS FOUND";
        }

        reasons.add(
                "Phone number format and message context alone cannot "
                + "confirm whether the caller is fraudulent.");

        return new AnalysisResult(
                risk,
                classification,
                new ArrayList<>(reasons));
    }

    private static boolean containsAny(
            String text, String[] phrases) {

        for (String phrase : phrases) {
            if (text.contains(phrase)) {
                return true;
            }
        }

        return false;
    }
}
