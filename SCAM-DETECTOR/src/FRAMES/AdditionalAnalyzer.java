package FRAMES;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.json.JSONArray;
import org.json.JSONObject;

public class AdditionalAnalyzer {

    private static final String API_URL =
            "https://api.groq.com/openai/v1/chat/completions";

    private static final String MODEL =
            "qwen/qwen3.8-27b";

    private static final HttpClient CLIENT =
            HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(20))
                    .build();

    private static final String PROMPT =
            "You are a scam detection assistant. Analyze the supplied "
            + "screenshot or text for scams, phishing, fraud, fake offers, "
            + "impersonation, suspicious links, OTP theft, payment fraud, "
            + "and other warning signs. Do not assume content is a scam "
            + "without evidence. Return your answer in exactly this format:\n"
            + "Classification: LOW RISK, SUSPICIOUS, or HIGH RISK\n"
            + "Risk Score: a number from 0 to 100\n"
            + "Warning signs: list the specific warning signs, or state "
            + "None identified\n"
            + "Explanation: briefly explain the assessment\n"
            + "Recommended action: give a safe next step\n"
            + "Do not claim a link or sender has been verified unless "
            + "you actually have evidence.";

    public static String analyzeText(String text) throws Exception {

        if (text == null || text.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "Text to analyze cannot be empty.");
        }

        return sendRequest(PROMPT + "\n\nAnalyze this text:\n" + text);
    }

    public static String analyzeScreenshot(Path imagePath)
            throws Exception {

        if (imagePath == null || !Files.isRegularFile(imagePath)) {
            throw new IOException("Screenshot file was not found.");
        }

        long fileSize = Files.size(imagePath);

        if (fileSize == 0 || fileSize > 10 * 1024 * 1024) {
            throw new IOException(
                    "Image must be larger than 0 bytes and no more "
                    + "than 10 MB.");
        }

        BufferedImage image = ImageIO.read(imagePath.toFile());

        if (image == null) {
            throw new IOException(
                    "Unsupported image. Use PNG, JPG, or JPEG.");
        }

        String fileName = imagePath.getFileName()
                .toString().toLowerCase();

        String mimeType;

        if (fileName.endsWith(".png")) {
            mimeType = "image/png";
        } else if (fileName.endsWith(".jpg")
                || fileName.endsWith(".jpeg")) {
            mimeType = "image/jpeg";
        } else {
            throw new IOException(
                    "Please use a PNG, JPG, or JPEG screenshot.");
        }

        byte[] imageBytes = Files.readAllBytes(imagePath);
        String base64Image =
                Base64.getEncoder().encodeToString(imageBytes);

        String dataUrl =
                "data:" + mimeType + ";base64," + base64Image;

        JSONArray content = new JSONArray();

        JSONObject textPart = new JSONObject();
        textPart.put("type", "text");
        textPart.put("text",
                PROMPT
                + "\n\nCarefully inspect this screenshot. Read visible "
                + "messages, sender details, URLs, payment requests, "
                + "and other relevant warning signs. Assess only what "
                + "is visible in the image.");

        content.put(textPart);

        JSONObject imageUrl = new JSONObject();
        imageUrl.put("url", dataUrl);

        JSONObject imagePart = new JSONObject();
        imagePart.put("type", "image_url");
        imagePart.put("image_url", imageUrl);

        content.put(imagePart);

        JSONObject userMessage = new JSONObject();
        userMessage.put("role", "user");
        userMessage.put("content", content);

        JSONArray messages = new JSONArray();
        messages.put(userMessage);

        return sendRequest(messages);
    }

    private static String sendRequest(String prompt)
            throws Exception {

        JSONArray messages = new JSONArray();

        JSONObject message = new JSONObject();
        message.put("role", "user");
        message.put("content", prompt);

        messages.put(message);

        return sendRequest(messages);
    }

    private static String sendRequest(JSONArray messages)
            throws Exception {

        String apiKey = System.getenv("GROQ_API_KEY");

        if (apiKey == null || apiKey.trim().isEmpty()) {
            throw new IllegalStateException(
                    "GROQ_API_KEY environment variable is missing.");
        }

        JSONObject requestBody = new JSONObject();
        requestBody.put("model", MODEL);
        requestBody.put("messages", messages);
        requestBody.put("temperature", 0.2);
        requestBody.put("max_completion_tokens", 800);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .timeout(Duration.ofSeconds(90))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(
                        requestBody.toString()))
                .build();

        HttpResponse<String> response = CLIENT.send(
                request,
                HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200
                || response.statusCode() >= 300) {

            throw new IOException(
                    "Groq API error (HTTP "
                    + response.statusCode()
                    + "). Check the API key, model access, "
                    + "connection, and request limits.");
        }

        JSONObject responseJson =
                new JSONObject(response.body());

        JSONArray choices = responseJson.optJSONArray("choices");

        if (choices == null || choices.length() == 0) {
            throw new IOException(
                    "Groq returned an empty response.");
        }

        JSONObject firstChoice = choices.getJSONObject(0);
        JSONObject assistantMessage =
                firstChoice.getJSONObject("message");

        String result = assistantMessage.optString(
                "content", "").trim();

        if (result.isEmpty()) {
            throw new IOException(
                    "Groq returned no analysis text.");
        }

        return result;
    }
}