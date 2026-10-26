
package FRAMES;

import java.util.ArrayList;
import java.util.Locale;
import java.util.regex.Pattern;

public class EmailAnalyzer {

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

    public static AnalysisResult analyze(String subject, String body) {

        ArrayList<String> reasons = new ArrayList<>();
        int risk = 0;

        if ((subject == null || subject.trim().isEmpty())
                && (body == null || body.trim().isEmpty())) {
            reasons.add("Please enter an email subject or body.");
            return new AnalysisResult(0, "INVALID INPUT", reasons);
        }

        String email = ((subject == null ? "" : subject) + " "
                + (body == null ? "" : body)).toLowerCase(Locale.ROOT);

        if (Pattern.compile("(https?://|www\\.)\\S+")
                .matcher(email).find()) {
            risk += 15;
            reasons.add("The email contains a web link.");
        }

        if (Pattern.compile(
                "(bit\\.ly|tinyurl\\.com|t\\.co|cutt\\.ly|rb\\.gy)")
                .matcher(email).find()) {
            risk += 20;
            reasons.add("The email contains a shortened link.");
        }

        String[] urgentWords = {
            "urgent", "act immediately", "act now",
            "account suspended", "account blocked",
            "within 24 hours", "final warning"
        };

        for (String word : urgentWords) {
            if (email.contains(word)) {
                risk += 15;
                reasons.add("Urgent language or account threats detected.");
                break;
            }
        }

        String[] sensitiveWords = {
            "share your otp", "send your otp",
            "enter your otp", "verify your password",
            "share your password", "credit card details",
            "cvv", "banking credentials"
        };

        for (String word : sensitiveWords) {
            if (email.contains(word)) {
                risk += 25;
                reasons.add("The email may request sensitive information.");
                break;
            }
        }

        String[] prizeWords = {
            "you have won", "you won a prize",
            "claim your prize", "lucky winner",
            "cash prize", "free gift"
        };

        for (String word : prizeWords) {
            if (email.contains(word)) {
                risk += 20;
                reasons.add("An unexpected prize or reward is mentioned.");
                break;
            }
        }

        String[] paymentWords = {
            "processing fee", "pay a fee",
            "send money", "transfer money",
            "payment required", "upi payment"
        };

        for (String word : paymentWords) {
            if (email.contains(word)) {
                risk += 20;
                reasons.add("A suspicious payment request may be present.");
                break;
            }
        }

        risk = Math.min(risk, 100);

        String classification;

        if (risk >= 50) {
            classification = "HIGH RISK - POSSIBLE SCAM";
        } else if (risk >= 20) {
            classification = "SUSPICIOUS - REVIEW CAREFULLY";
        } else {
            classification = "LOW RISK - NO MAJOR FLAGS FOUND";
        }

        if (reasons.isEmpty()) {
            reasons.add("No warning signs were detected by these rules.");
        }

        return new AnalysisResult(risk, classification, reasons);
    }
}
