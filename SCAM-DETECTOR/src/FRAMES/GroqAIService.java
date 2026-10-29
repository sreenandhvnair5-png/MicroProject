package FRAMES;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.json.JSONArray;
import org.json.JSONObject;

public class GroqAIService {

    private static final String API_URL =
            "https://api.groq.com/openai/v1/chat/completions";

    private static final String MODEL = "qwen/qwen3.8-27b";

    private static final HttpClient CLIENT =
            HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(15))
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

        if (content == null || content.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "Content to analyze cannot be empty.");
        }

        String apiKey = GroqConfig.API_KEY;

        if (apiKey == null
                || apiKey.trim().isEmpty()
                || apiKey.equals("PASTE_YOUR_GROQ_API_KEY_HERE")) {

            throw new IllegalStateException(
                    "Groq API key is missing. "
                    + "Check the API_KEY value in GroqConfig.java.");
        }

        String prompt =
                "You are a scam detection assistant. Analyze the supplied "
                + "content and identify evidence of scams, phishing, fraud, "
                + "impersonation, suspicious links, OTP theft, and payment "
                + "fraud. Do not assume content is fraudulent without evidence. "
                + "Return ONLY a valid JSON object with these exact fields: "
                + "\"classification\" (SAFE, SUSPICIOUS, or HIGH RISK), "
                + "\"riskScore\" (integer 0 to 100), "
                + "\"reasons\" (string explaining warning signs), "
                + "\"explanation\" (string explaining the assessment). "
                + "Do not claim a sender or URL is verified unless evidence "
                + "supports that claim.\n\n"
                + "Content type: " + type
                + "\nContent to analyze:\n" + content;

        JSONObject requestBody = new JSONObject();
        requestBody.put("model", MODEL);
        requestBody.put("temperature", 0.2);
        requestBody.put("max_completion_tokens", 800);
        requestBody.put("messages", new JSONArray()
                .put(new JSONObject()
                        .put("role", "user")
                        .put("content", prompt)));

        requestBody.put("response_format",
                new JSONObject().put("type", "json_object"));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .timeout(Duration.ofSeconds(60))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + apiKey.trim())
                .POST(HttpRequest.BodyPublishers.ofString(
                        requestBody.toString()))
                .build();

        HttpResponse<String> response = CLIENT.send(
                request,
                HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200
                || response.statusCode() >= 300) {
            throw new IOException(
                    "Groq API error (HTTP " + response.statusCode()
                    + "). Check your API key, model access, internet "
                    + "connection, and API limits.");
        }

        JSONObject responseJson = new JSONObject(response.body());
        JSONArray choices = responseJson.optJSONArray("choices");

        if (choices == null || choices.length() == 0) {
            throw new IOException("Groq returned an empty response.");
        }

        String answer = choices.getJSONObject(0)
                .getJSONObject("message")
                .optString("content", "").trim();

        if (answer.isEmpty()) {
            throw new IOException("Groq returned no analysis text.");
        }

        JSONObject result = new JSONObject(answer);

        String classification =
                result.getString("classification").trim().toUpperCase();

        int riskScore = result.getInt("riskScore");
        String reasons = result.optString("reasons", "");
        String explanation = result.optString("explanation", "");

        if (!classification.equals("SAFE")
                && !classification.equals("SUSPICIOUS")
                && !classification.equals("HIGH RISK")) {
            throw new IOException("Groq returned an invalid classification.");
        }

        if (riskScore < 0 || riskScore > 100) {
            throw new IOException("Groq returned an invalid risk score.");
        }

        return new AIResult(
                classification, riskScore, reasons, explanation);
    }
}
