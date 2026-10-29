
package FRAMES;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EmailAnalyzer {

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

    private static final Pattern SHORT_URL_PATTERN = Pattern.compile(
            "(?i)(bit\\.ly|tinyurl\\.com|t\\.co|cutt\\.ly|rb\\.gy"
            + "|is\\.gd|rebrand\\.ly|ow\\.ly|buff\\.ly|lnkd\\.in)"
            + "(?:/|\\b)");

    private static final Pattern CREDENTIAL_REQUEST_PATTERN =
            Pattern.compile(
                    "(?i)\\b(?:share|send|provide|reveal|enter|confirm)"
                    + "\\s+(?:me\\s+)?(?:your\\s+)?"
                    + "(?:otp|one[- ]time password|password|pin|cvv|"
                    + "credit card details|banking credentials|"
                    + "login credentials|account credentials)\\b");

    private static final Pattern EMAIL_ADDRESS_PATTERN =
            Pattern.compile(
                    "(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b");

    private static final String[] URGENCY_PHRASES = {
            "urgent", "act immediately", "act now",
            "account suspended", "account blocked",
            "within 24 hours", "within 2 hours",
            "final warning", "last warning",
            "immediate action required", "your account will be closed",
            "failure to comply"
    };

    private static final String[] BANK_KYC_PHRASES = {
            "update your kyc", "complete your kyc",
            "kyc expired", "kyc verification",
            "verify your bank account", "account reactivation",
            "update pan details", "bank account will be blocked",
            "verify your account immediately"
    };

    private static final String[] PRIZE_PHRASES = {
            "you have won", "you won a prize",
            "claim your prize", "lucky winner",
            "cash prize", "free gift",
            "lottery winner", "claim your reward",
            "guaranteed reward", "selected for a prize"
    };

    private static final String[] PAYMENT_PHRASES = {
            "processing fee", "pay a fee",
            "send money", "transfer money",
            "payment required", "upi payment",
            "release fee", "refundable deposit",
            "claim fee", "pay to receive",
            "payment confirmation required"
    };

    private static final String[] REMOTE_ACCESS_PHRASES = {
            "install anydesk", "install teamviewer",
            "install remote access", "share your screen",
            "enable screen sharing", "install this apk",
            "download this application"
    };

    private static final String[] IMPERSONATION_PHRASES = {
            "bank security team", "bank customer support",
            "customer care department", "income tax department",
            "government officer", "police department",
            "your account will be suspended",
            "official verification team", "account security team"
    };

    private static final String[] ATTACHMENT_PHRASES = {
            "open the attached file", "enable macros",
            "enable content to view", "download the attached file",
            "open this invoice attachment",
            "view the attached document immediately"
    };

    private static final String[] SECRECY_PHRASES = {
            "do not tell anyone", "don't tell anyone",
            "keep this confidential", "do not contact your bank",
            "keep this secret", "do not discuss this with anyone"
    };

    private static final String[] AWARENESS_PHRASES = {
            "never share your otp",
            "do not share your otp",
            "don't share your otp",
            "never share your password",
            "do not share your password",
            "don't share your password",
            "fraud awareness",
            "scam awareness",
            "security awareness",
            "example of a phishing email",
            "example of a scam email"
    };

    public static AnalysisResult analyze(
            String subject, String body) {

        Set<String> reasons = new LinkedHashSet<>();
        int risk = 0;

        if ((subject == null || subject.trim().isEmpty())
                && (body == null || body.trim().isEmpty())) {

            ArrayList<String> invalidReasons = new ArrayList<>();
            invalidReasons.add(
                    "Please enter an email subject or body.");

            return new AnalysisResult(
                    0, "INVALID INPUT", invalidReasons);
        }

        String subjectText = subject == null ? "" : subject.trim();
        String bodyText = body == null ? "" : body.trim();

        String email = (subjectText + " " + bodyText)
                .toLowerCase(Locale.ROOT)
                .replace('\u2019', '\'')
                .replace('\u2018', '\'');

        // Avoid flagging educational security warnings as attacks.
        for (String phrase : AWARENESS_PHRASES) {
            if (email.contains(phrase)) {
                reasons.add(
                        "The email appears to contain security advice "
                        + "or fraud-awareness content.");

                return new AnalysisResult(
                        0,
                        "LOW RISK - POSSIBLE AWARENESS CONTENT",
                        new ArrayList<>(reasons));
            }
        }

        // 1. URL detection.
        boolean hasUrl = URL_PATTERN.matcher(email).find();

        if (hasUrl) {
            risk += 5;
            reasons.add(
                    "The email contains a URL. A link alone does not "
                    + "prove that an email is fraudulent.");
        }

        // 2. Shortened URL detection.
        boolean hasShortUrl =
                SHORT_URL_PATTERN.matcher(email).find();

        if (hasShortUrl) {
            risk += 15;
            reasons.add(
                    "The email contains a shortened URL that can hide "
                    + "the final destination.");
        }

        // 3. Urgency and threats.
        boolean hasUrgency =
                containsAny(email, URGENCY_PHRASES);

        if (hasUrgency) {
            risk += 15;
            reasons.add(
                    "Urgent deadlines or account-related pressure "
                    + "tactics were detected.");
        }

        // 4. Requests for sensitive credentials.
        boolean credentialRequest =
                CREDENTIAL_REQUEST_PATTERN.matcher(email).find();

        if (credentialRequest) {
            risk += 35;
            reasons.add(
                    "The email appears to request sensitive information "
                    + "such as an OTP, password, PIN, CVV, or "
                    + "account credentials.");
        }

        // 5. OTP mentioned alongside a link.
        boolean mentionsOtp =
                email.contains("otp")
                || email.contains("one-time password");

        if (mentionsOtp && hasUrl && !credentialRequest) {
            risk += 10;
            reasons.add(
                    "An OTP is mentioned alongside a URL. Verify the "
                    + "destination before taking any action.");
        }

        // 6. KYC and banking-related claims.
        boolean bankKyc =
                containsAny(email, BANK_KYC_PHRASES);

        if (bankKyc) {
            risk += 20;
            reasons.add(
                    "Banking, KYC, or account-verification claims "
                    + "were detected.");
        }

        // 7. Unexpected prizes and rewards.
        boolean prize =
                containsAny(email, PRIZE_PHRASES);

        if (prize) {
            risk += 20;
            reasons.add(
                    "The email promises an unexpected prize, lottery "
                    + "win, or reward.");
        }

        // 8. Payment requests.
        boolean payment =
                containsAny(email, PAYMENT_PHRASES);

        if (payment) {
            risk += 20;
            reasons.add(
                    "The email contains a fee, payment, or "
                    + "money-transfer request.");
        }

        // 9. Remote access and app installation.
        boolean remoteAccess =
                containsAny(email, REMOTE_ACCESS_PHRASES);

        if (remoteAccess) {
            risk += 25;
            reasons.add(
                    "The email asks the recipient to install software "
                    + "or share remote access to a device.");
        }

        // 10. Claims of official identity.
        boolean impersonation =
                containsAny(email, IMPERSONATION_PHRASES);

        if (impersonation) {
            risk += 10;
            reasons.add(
                    "The email claims an official or organizational "
                    + "identity that has not been verified.");
        }

        // 11. Suspicious attachment instructions.
        boolean attachment =
                containsAny(email, ATTACHMENT_PHRASES);

        if (attachment) {
            risk += 15;
            reasons.add(
                    "The email contains instructions to open an "
                    + "attachment or enable potentially risky content.");
        }

        // 12. Secrecy and isolation tactics.
        boolean secrecy =
                containsAny(email, SECRECY_PHRASES);

        if (secrecy) {
            risk += 15;
            reasons.add(
                    "The email discourages independent verification "
                    + "or asks the recipient to keep the matter secret.");
        }

        // 13. Sender addresses are not proof of identity.
        Matcher addressMatcher =
                EMAIL_ADDRESS_PATTERN.matcher(subjectText
                        + " " + bodyText);

        boolean hasEmailAddress = addressMatcher.find();

        if (hasEmailAddress) {
            reasons.add(
                    "An email address was found in the supplied text. "
                    + "This analyzer does not verify the sender's "
                    + "identity or email authentication records.");
        }

        // 14. Multiple independent indicators.
        int indicators = 0;

        if (hasUrl) indicators++;
        if (hasUrgency) indicators++;
        if (credentialRequest) indicators++;
        if (bankKyc) indicators++;
        if (prize) indicators++;
        if (payment) indicators++;
        if (remoteAccess) indicators++;
        if (secrecy) indicators++;

        if (indicators >= 3) {
            risk += 10;
            reasons.add(
                    "Several independent warning signs appear together, "
                    + "increasing concern about phishing or fraud.");
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

        if (reasons.isEmpty()) {
            reasons.add(
                    "No significant warning signs were detected by "
                    + "these rules. This does not guarantee that "
                    + "the email is safe.");
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
}
