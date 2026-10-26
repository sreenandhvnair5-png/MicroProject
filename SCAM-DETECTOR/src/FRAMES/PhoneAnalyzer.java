
package FRAMES;

import java.util.ArrayList;
import java.util.Locale;

public class PhoneAnalyzer {

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

    public static AnalysisResult analyze(String phone, String context) {

        ArrayList<String> reasons = new ArrayList<>();
        int risk = 0;

        if (phone == null || phone.trim().isEmpty()) {
            reasons.add("Please enter a phone number.");
            return new AnalysisResult(0, "INVALID INPUT", reasons);
        }

        // Keep only digits for basic format checking.
        String digits = phone.replaceAll("\\D", "");

        // Accept Indian numbers with or without country code 91.
        if (digits.startsWith("91") && digits.length() == 12) {
            digits = digits.substring(2);
        }

        if (digits.length() != 10 || digits.charAt(0) < '6'
                || digits.charAt(0) > '9') {

            reasons.add("The number does not match a typical Indian mobile format.");
            reasons.add("The country code or number may be invalid for this scanner.");

            return new AnalysisResult(
                    0,
                    "INVALID FORMAT - UNABLE TO ASSESS",
                    reasons
            );
        }

        String text = context == null
                ? ""
                : context.toLowerCase(Locale.ROOT);

        String[] scamPhrases = {
            "share your otp", "send your otp", "account blocked",
            "account suspended", "verify your bank account",
            "send money", "pay a processing fee",
            "claim your prize", "you have won",
            "remote access", "install this app"
        };

        for (String phrase : scamPhrases) {
            if (text.contains(phrase)) {
                risk += 30;
                reasons.add("Potential scam-related language detected: " + phrase);
                break;
            }
        }

        if (text.contains("urgent") || text.contains("act now")
                || text.contains("immediately")) {
            risk += 15;
            reasons.add("Urgent or pressuring language detected.");
        }

        if (text.contains("http://") || text.contains("https://")
                || text.contains("www.")) {
            risk += 15;
            reasons.add("The message includes a web link.");
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
            reasons.add("No warning signs were detected in the supplied context.");
        }

        reasons.add("Phone format alone cannot establish whether a caller is fraudulent.");

        return new AnalysisResult(risk, classification, reasons);
    }
}
