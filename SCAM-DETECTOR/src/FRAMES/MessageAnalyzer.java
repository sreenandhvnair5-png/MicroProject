
package FRAMES;

import java.util.ArrayList;
import java.util.Locale;
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

    public static AnalysisResult analyze(String message) {

        ArrayList<String> reasons = new ArrayList<>();
        int risk = 0;

        if (message == null || message.trim().isEmpty()) {
            reasons.add("Please enter a message to scan.");
            return new AnalysisResult(
                    0, "INVALID INPUT", reasons);
        }

        String text = message.toLowerCase(Locale.ROOT);

        // 1. Check for links in the message
        if (Pattern.compile(
                "(https?://|www\\.)\\S+",
                Pattern.CASE_INSENSITIVE).matcher(text).find()) {

            risk += 15;
            reasons.add("The message contains a web link.");
        }

        // 2. Check for shortened links often used to hide destinations
        if (Pattern.compile(
                "(bit\\.ly|tinyurl\\.com|t\\.co|cutt\\.ly|rb\\.gy)",
                Pattern.CASE_INSENSITIVE).matcher(text).find()) {

            risk += 20;
            reasons.add("The message contains a shortened link.");
        }

        // 3. Check for urgency or threats
        String[] urgentWords = {
                "urgent", "immediately", "act now",
                "within 24 hours", "account blocked",
                "account suspended", "will be blocked"
        };

        for (String word : urgentWords) {
            if (text.contains(word)) {
                risk += 15;
                reasons.add("Urgent language or account threats detected.");
                break;
            }
        }

        // 4. Check for requests for sensitive information
        String[] sensitiveWords = {
                "share your otp", "send your otp",
                "enter your otp", "verify your password",
                "share your password", "pin number",
                "cvv", "card details"
        };

        for (String word : sensitiveWords) {
            if (text.contains(word)) {
                risk += 25;
                reasons.add("The message may request sensitive information.");
                break;
            }
        }

        // 5. Check for prizes or unexpected rewards
        String[] prizeWords = {
                "you have won", "you won",
                "claim your prize", "lucky winner",
                "free gift", "cash prize"
        };

        for (String word : prizeWords) {
            if (text.contains(word)) {
                risk += 20;
                reasons.add("An unexpected prize or reward is mentioned.");
                break;
            }
        }

        // 6. Check for money transfer or payment pressure
        String[] paymentWords = {
                "send money", "pay now",
                "transfer money", "upi payment",
                "processing fee", "pay a fee",
                "bank account blocked"
        };

        for (String word : paymentWords) {
            if (text.contains(word)) {
                risk += 20;
                reasons.add("The message contains a payment-related warning sign.");
                break;
            }
        }

        // Keep score within 0 to 100
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
            reasons.add(
                    "No warning signs were detected by these basic rules.");
        }

        return new AnalysisResult(
                risk, classification, reasons);
    }
}
