
package FRAMES;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MessageAnalyzer {

    public static class AnalysisResult {
        public int riskScore;
        public String classification;
        public ArrayList<String> reasons;

        public AnalysisResult(int riskScore,
                              String classification,
                              ArrayList<String> reasons) {
            this.riskScore = riskScore;
            this.classification = classification;
            this.reasons = reasons;
        }
    }

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)(https?://|www\\.)\\S+");

    private static final Pattern SHORT_URL_PATTERN = Pattern.compile(
            "(?i)(bit\\.ly|tinyurl\\.com|t\\.co|cutt\\.ly|rb\\.gy"
            + "|is\\.gd|shorturl\\.at|rebrand\\.ly|ow\\.ly"
            + "|buff\\.ly|lnkd\\.in)(?:/|\\b)");

    private static final Pattern IP_URL_PATTERN = Pattern.compile(
            "(?i)https?://(?:\\d{1,3}\\.){3}\\d{1,3}"
            + "(?::\\d+)?(?:/|\\b)");

    private static final Pattern URL_WITH_AT_PATTERN = Pattern.compile(
            "(?i)https?://[^\\s/]+@");

    private static final Pattern CREDENTIAL_PATTERN = Pattern.compile(
            "(?i)\\b(?:share|send|tell|provide|reveal|submit)"
            + "\\s+(?:me\\s+)?(?:your\\s+)?"
            + "(?:otp|one[- ]time password|password|pin|cvv"
            + "|card number|bank details|login credentials)\\b");

    private static final Pattern OTP_PATTERN = Pattern.compile(
            "(?i)\\b(?:otp|one[- ]time password)\\b");

    private static final Pattern PAYMENT_REQUEST_PATTERN = Pattern.compile(
            "(?i)\\b(?:send|transfer|pay|deposit|remit)"
            + "\\s+(?:the\\s+)?(?:money|amount|funds|fee|deposit)"
            + "\\b");

    private static final Pattern UPI_REQUEST_PATTERN = Pattern.compile(
            "(?i)\\b(?:scan|approve|accept|authorize)"
            + "\\s+(?:the\\s+)?(?:upi\\s+)?"
            + "(?:collect request|payment request|payment)\\b");

    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "(?<!\\w)(?:\\+?\\d[\\d\\s().-]{7,}\\d)(?!\\w)");

    private static final String[] URGENCY_PHRASES = {
            "urgent", "immediately", "act now",
            "within 24 hours", "within 2 hours",
            "within 1 hour", "expires today",
            "final warning", "last warning",
            "limited time", "respond now",
            "failure to comply", "account will be blocked",
            "account will be suspended",
            "account has been suspended",
            "account will be closed"
    };

    private static final String[] BANK_IMPERSONATION = {
            "sbi", "hdfc bank", "icici bank",
            "axis bank", "kotak bank", "pnb",
            "reserve bank of india", "rbi",
            "bank customer support", "bank security team",
            "bank verification team"
    };

    private static final String[] KYC_PHRASES = {
            "complete your kyc", "update your kyc",
            "kyc expired", "kyc verification",
            "kyc update required", "verify your bank account",
            "account re-kyc", "pan card update required",
            "update pan details"
    };

    private static final String[] CREDENTIAL_REQUESTS = {
            "enter your password", "verify your password",
            "confirm your password", "share your password",
            "send your otp", "share your otp",
            "enter your otp", "provide your otp",
            "tell me your otp", "share your pin",
            "enter your pin", "share your cvv",
            "provide your card details",
            "send your bank details",
            "verify your login credentials"
    };

    private static final String[] PRIZE_PHRASES = {
            "you have won", "you won",
            "claim your prize", "lucky winner",
            "free gift", "cash prize",
            "congratulations winner", "won a lottery",
            "lottery winner", "claim your reward",
            "selected for a prize", "guaranteed reward"
    };

    private static final String[] INVESTMENT_PHRASES = {
            "guaranteed returns", "double your money",
            "risk-free investment", "daily guaranteed profit",
            "100% profit guaranteed", "get rich quickly",
            "guaranteed profit", "instant high returns"
    };

    private static final String[] THREAT_PHRASES = {
            "legal action will be taken",
            "police will arrest you",
            "warrant issued against you",
            "your account will be frozen",
            "your sim will be blocked",
            "electricity will be disconnected",
            "service will be disconnected",
            "your parcel is held",
            "pay the fine immediately"
    };

    private static final String[] PAYMENT_PRESSURE = {
            "processing fee", "pay a fee",
            "registration fee", "refundable deposit",
            "pay now", "send money",
            "transfer money", "upi payment",
            "claim fee", "release fee",
            "advance payment required",
            "pay to receive your prize",
            "pay to unlock your account"
    };

    private static final String[] REMOTE_ACCESS_PHRASES = {
            "install anydesk", "install teamviewer",
            "install remote access", "download remote access",
            "share your screen", "enable screen sharing",
            "install this apk", "install this application"
    };

    private static final String[] SUSPICIOUS_CONTACT_PHRASES = {
            "contact me on whatsapp",
            "message me on telegram",
            "move to telegram",
            "continue on whatsapp",
            "do not contact your bank",
            "do not tell anyone",
            "keep this confidential",
            "do not tell your family"
    };

    private static final String[] BENIGN_CONTEXT_PHRASES = {
            "never share your otp",
            "do not share your otp",
            "don't share your otp",
            "never share your password",
            "do not share your password",
            "don't share your password",
            "never share your pin",
            "do not share your pin",
            "don't share your pin",
            "never click suspicious links",
            "this is a security awareness message",
            "this is a fraud awareness message",
            "example of a scam message",
            "scam awareness",
            "fraud awareness"
    };

    public static AnalysisResult analyze(String message) {

        Set<String> reasons = new LinkedHashSet<>();
        int risk = 0;

        if (message == null || message.trim().isEmpty()) {
            ArrayList<String> invalidReasons = new ArrayList<>();
            invalidReasons.add("Please enter a message to scan.");

            return new AnalysisResult(
                    0, "INVALID INPUT", invalidReasons);
        }

        String text = message.toLowerCase(Locale.ROOT)
                .replace('\u2019', '\'')
                .replace('\u2018', '\'');

        // Educational or protective messages should not be
        // treated as malicious solely because they mention scams.
        boolean awarenessContext = containsAny(
                text, BENIGN_CONTEXT_PHRASES);

        if (awarenessContext) {
            reasons.add(
                    "The message appears to contain fraud-awareness "
                    + "or protective advice; interpret other indicators "
                    + "with caution.");

            ArrayList<String> awarenessReasons =
                    new ArrayList<>(reasons);

            return new AnalysisResult(
                    0, "LOW RISK - NO MAJOR FLAGS FOUND",
                    awarenessReasons);
        }

        // 1. Links and URL risk indicators.
        boolean hasUrl = URL_PATTERN.matcher(text).find();

        if (hasUrl) {
            risk += 5;
            reasons.add(
                    "The message contains a URL. A link alone does "
                    + "not prove that the message is fraudulent.");
        }

        boolean hasShortUrl =
                SHORT_URL_PATTERN.matcher(text).find();

        if (hasShortUrl) {
            risk += 15;
            reasons.add(
                    "A URL-shortening service is present, which can "
                    + "hide the destination website.");
        }

        if (IP_URL_PATTERN.matcher(text).find()) {
            risk += 25;
            reasons.add(
                    "The URL uses an IP address instead of a "
                    + "recognizable domain name.");
        }

        if (URL_WITH_AT_PATTERN.matcher(text).find()) {
            risk += 25;
            reasons.add(
                    "The URL contains an @ character in its authority "
                    + "section, which can disguise the destination.");
        }

        // 2. Urgency and threats.
        boolean hasUrgency = containsAny(text, URGENCY_PHRASES);

        if (hasUrgency) {
            risk += 10;
            reasons.add(
                    "Pressure tactics or urgent deadlines are present.");
        }

        boolean hasThreat = containsAny(text, THREAT_PHRASES);

        if (hasThreat) {
            risk += 20;
            reasons.add(
                    "The message uses threats involving legal action, "
                    + "service interruption, or account restrictions.");
        }

        // 3. Requests for credentials or OTPs.
        boolean hasCredentialRequest =
                CREDENTIAL_REQUEST_PATTERN().matcher(text).find()
                || containsAny(text, CREDENTIAL_REQUESTS);

        boolean mentionsOtp = OTP_PATTERN.matcher(text).find();

        if (hasCredentialRequest) {
            risk += 35;
            reasons.add(
                    "The message appears to request sensitive "
                    + "credentials such as an OTP, password, PIN, "
                    + "CVV, or bank details.");
        } else if (mentionsOtp && hasUrl) {
            risk += 15;
            reasons.add(
                    "An OTP is mentioned alongside a link. Verify "
                    + "the destination before taking any action.");
        }

        // 4. Banking and KYC impersonation patterns.
        boolean mentionsBank = containsAny(text, BANK_IMPERSONATION);
        boolean mentionsKyc = containsAny(text, KYC_PHRASES);

        if (mentionsBank && mentionsKyc) {
            risk += 20;
            reasons.add(
                    "Bank-related identity or KYC claims are combined "
                    + "with a request to update or verify details.");
        } else if (mentionsKyc && hasUrl) {
            risk += 15;
            reasons.add(
                    "A KYC or account-verification claim is combined "
                    + "with a link.");
        }

        // 5. Prize, lottery, and reward scams.
        boolean hasPrize = containsAny(text, PRIZE_PHRASES);

        if (hasPrize) {
            risk += 20;
            reasons.add(
                    "The message promises an unexpected prize, "
                    + "lottery win, or reward.");
        }

        // 6. Financial pressure and investment promises.
        boolean hasPaymentPressure =
                containsAny(text, PAYMENT_PRESSURE);

        boolean hasPaymentRequest =
                PAYMENT_REQUEST_PATTERN.matcher(text).find()
                || UPI_REQUEST_PATTERN.matcher(text).find();

        if (hasPaymentPressure || hasPaymentRequest) {
            risk += 15;
            reasons.add(
                    "The message encourages a payment, transfer, "
                    + "fee, or payment approval.");
        }

        if (containsAny(text, INVESTMENT_PHRASES)) {
            risk += 25;
            reasons.add(
                    "The message makes unusually strong or guaranteed "
                    + "investment-return claims.");
        }

        // 7. Remote access and suspicious app installation.
        if (containsAny(text, REMOTE_ACCESS_PHRASES)) {
            risk += 25;
            reasons.add(
                    "The message asks the recipient to install an app, "
                    + "enable remote access, or share their screen.");
        }

        // 8. Attempts to isolate the recipient or move conversations.
        if (containsAny(text, SUSPICIOUS_CONTACT_PHRASES)) {
            risk += 15;
            reasons.add(
                    "The message contains secrecy instructions or "
                    + "requests to move the conversation to another "
                    + "messaging platform.");
        }

        // 9. Multiple warning signs increase concern.
        // Add a combination bonus once, not once per pair.
        int majorIndicators = 0;

        if (hasUrl) majorIndicators++;
        if (hasUrgency) majorIndicators++;
        if (hasCredentialRequest) majorIndicators++;
        if (hasPrize) majorIndicators++;
        if (hasPaymentPressure || hasPaymentRequest) {
            majorIndicators++;
        }
        if (mentionsKyc && mentionsBank) majorIndicators++;
        if (hasThreat) majorIndicators++;

        if (majorIndicators >= 3) {
            risk += 15;
            reasons.add(
                    "Several independent warning signs occur together, "
                    + "increasing the likelihood of a scam attempt.");
        }

        // Keep score within the supported range.
        risk = Math.min(risk, 100);

        String classification;

        if (risk >= 60) {
            classification = "HIGH RISK - POSSIBLE SCAM";
        } else if (risk >= 25) {
            classification = "SUSPICIOUS - REVIEW CAREFULLY";
        } else {
            classification = "LOW RISK - NO MAJOR FLAGS FOUND";
        }

        if (reasons.isEmpty()) {
            reasons.add(
                    "No significant warning signs were detected by "
                    + "the current rule-based checks. This does not "
                    + "guarantee that the message is safe.");
        }

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

    private static Pattern CREDENTIAL_REQUEST_PATTERN() {
        return Pattern.compile(
                "(?i)\\b(?:ask|asking|request|requesting)"
                + "\\s+(?:for\\s+)?(?:your\\s+)?"
                + "(?:otp|password|pin|cvv|bank details|card details)\\b");
    }
}
