
package FRAMES;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GroqAIService {

	private static final String SUPABASE_URL =
		    "https://pwdgvyqeskwnumqeosaq.supabase.co/functions/v1/scam-analyze";

    private static final String SUPABASE_PUBLISHABLE_KEY =
        "sb_publishable_kwSsttjTjStIFD_yBqf0hQ_D4HhLGlK";

    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build();

    public static class AIResult {
        public String classification;
        public int riskScore;
        public String reasons;
        public String explanation;

        public AIResult(String classification, int riskScore,
                String reasons, String explanation) {
            this.classification = classification;
            this.riskScore = riskScore;
            this.reasons = reasons;
            this.explanation = explanation;
        }
    }

    public static AIResult analyze(String type, String content)
            throws Exception {

        String requestBody = "{\"type\":\"" + escapeJson(type)
                + "\",\"content\":\"" + escapeJson(content) + "\"}";

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(SUPABASE_URL))
            .timeout(Duration.ofSeconds(40))
            .header("apikey", SUPABASE_PUBLISHABLE_KEY)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();

        HttpResponse<String> response = CLIENT.send(
            request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200
                || response.statusCode() >= 300) {
            throw new Exception("Supabase returned HTTP "
                + response.statusCode() + ": " + response.body());
        }

        String body = response.body();

        String classification = extractString(body, "classification");
        String riskText = extractNumber(body, "riskScore");
        String reasons = extractString(body, "reasons");
        String explanation = extractString(body, "explanation");

        int riskScore = Integer.parseInt(riskText);

        if (riskScore < 0 || riskScore > 100) {
            throw new Exception("Invalid risk score.");
        }

        if (!classification.equals("SAFE")
                && !classification.equals("SUSPICIOUS")
                && !classification.equals("HIGH RISK")) {
            throw new Exception("Invalid classification.");
        }

        return new AIResult(
            classification, riskScore, reasons, explanation);
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    private static String extractString(String json, String key)
            throws Exception {

        Pattern pattern = Pattern.compile(
            "\"" + Pattern.quote(key)
            + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");

        Matcher matcher = pattern.matcher(json);

        if (!matcher.find()) {
            throw new Exception("Could not read field: " + key);
        }

        return unescapeJson(matcher.group(1));
    }

    private static String extractNumber(String json, String key)
            throws Exception {

        Pattern pattern = Pattern.compile(
            "\"" + Pattern.quote(key)
            + "\"\\s*:\\s*(\\d+)");

        Matcher matcher = pattern.matcher(json);

        if (!matcher.find()) {
            throw new Exception("Could not read number: " + key);
        }

        return matcher.group(1);
    }

    private static String unescapeJson(String value) {
        return value.replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\t", "\t")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }
}
