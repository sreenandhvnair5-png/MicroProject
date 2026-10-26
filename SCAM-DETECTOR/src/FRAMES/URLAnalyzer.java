package FRAMES;

import java.net.URI;
import java.util.ArrayList;

public class URLAnalyzer {

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

    public static AnalysisResult analyze(String input) {

        ArrayList<String> reasons = new ArrayList<>();
        int risk = 0;

        if (input == null || input.trim().isEmpty()) {
            reasons.add("Please enter a website URL.");
            return new AnalysisResult(
                    0, "INVALID INPUT", reasons);
        }

        String url = input.trim();

        if (!url.matches("(?i)^https?://.*")) {
            url = "https://" + url;
        }

        URI uri;

        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException ex) {
            reasons.add("The URL format is invalid.");
            return new AnalysisResult(
                    0, "INVALID INPUT", reasons);
        }

        String host = uri.getHost();

        if (host == null || host.isEmpty()) {
            reasons.add("A valid website domain could not be identified.");
            return new AnalysisResult(
                    0, "INVALID INPUT", reasons);
        }

        host = host.toLowerCase();

        // Check whether HTTPS is used
        if ("http".equalsIgnoreCase(uri.getScheme())) {
            risk += 15;
            reasons.add("The website uses HTTP instead of HTTPS.");
        }

        // Check for IP-address URLs
        if (host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            risk += 25;
            reasons.add("The URL uses an IP address instead of a domain name.");
        }

        // Check for unusually long URLs
        if (url.length() > 100) {
            risk += 10;
            reasons.add("The URL is unusually long.");
        }

        // Check for suspicious words in the URL
        String lowerUrl = url.toLowerCase();

        String[] suspiciousWords = {
                "verify", "login", "password",
                "wallet", "free-gift", "urgent"
        };

        for (String word : suspiciousWords) {
            if (lowerUrl.contains(word)) {
                risk += 10;
                reasons.add(
                        "The URL contains a potentially suspicious term: "
                                + word);
                break;
            }
        }

        // Keep risk score between 0 and 100
        risk = Math.min(risk, 100);

        String classification;

        if (risk >= 50) {
            classification = "SUSPICIOUS";
        } else if (risk >= 20) {
            classification = "NEEDS REVIEW";
        } else {
            classification = "NO OBVIOUS WARNING SIGNS";
        }

        if (reasons.isEmpty()) {
            reasons.add("No warning signs were detected by these basic rules.");
        }

        return new AnalysisResult(
                risk, classification, reasons);
    }
}