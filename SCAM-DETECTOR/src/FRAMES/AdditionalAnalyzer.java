
package FRAMES;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.time.Duration;

public class AdditionalAnalyzer {

	private static final String MODEL = "gemini-3.6-flash";

    private static final String API_URL =
            "https://generativelanguage.googleapis.com/"
          + "v1beta/models/" + MODEL + ":generateContent";

    private static final HttpClient CLIENT =
            HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(15))
                    .build();

    // Analyze messages, emails, or other text.
    public static String analyzeText(String text) throws Exception {

        if (text == null || text.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "Please provide text to analyze.");
        }

        String prompt =
                "You are an assistant for a scam detection system. "
              + "Analyze the supplied text for possible phishing, "
              + "impersonation, OTP or password requests, threats, "
              + "fake prizes, suspicious payments, and malicious links.\n\n"
              + "Return the following:\n"
              + "1. Classification: HIGH RISK, SUSPICIOUS, or LOW RISK\n"
              + "2. Risk score from 0 to 100\n"
              + "3. Warning signs\n"
              + "4. Explanation\n"
              + "5. Recommended action\n\n"
              + "Do not claim certainty. A low score does not "
              + "guarantee that the content is safe.\n\n"
              + "Text to analyze:\n"
              + text;

        return sendRequest(prompt, null, null);
    }

    // Analyze an uploaded screenshot directly without OCR.
    public static String analyzeScreenshot(Path imagePath)
            throws Exception {

        if (imagePath == null || !Files.isRegularFile(imagePath)) {
            throw new IllegalArgumentException(
                    "The selected image could not be found.");
        }

        String fileName = imagePath.getFileName()
                                   .toString()
                                   .toLowerCase();

        String mimeType;

        if (fileName.endsWith(".png")) {
            mimeType = "image/png";
        } else if (fileName.endsWith(".jpg")
                || fileName.endsWith(".jpeg")) {
            mimeType = "image/jpeg";
        } else if (fileName.endsWith(".webp")) {
            mimeType = "image/webp";
        } else {
            throw new IllegalArgumentException(
                    "Choose a PNG, JPG, JPEG, or WEBP image.");
        }

        byte[] imageBytes = Files.readAllBytes(imagePath);

        if (imageBytes.length > 10 * 1024 * 1024) {
            throw new IllegalArgumentException(
                    "Choose an image smaller than 10 MB.");
        }

        String base64Image = Base64.getEncoder()
                                   .encodeToString(imageBytes);

        String prompt =
                "Analyze this screenshot for possible scams. "
              + "Read the visible text and inspect the context. "
              + "Look for phishing links, impersonation, OTP or "
              + "password requests, threats, fake prizes, and "
              + "payment pressure.\n\n"
              + "Return:\n"
              + "1. Classification: HIGH RISK, SUSPICIOUS, or LOW RISK\n"
              + "2. Risk score from 0 to 100\n"
              + "3. Summary of visible text\n"
              + "4. Warning signs\n"
              + "5. Explanation\n"
              + "6. Recommended action\n\n"
              + "Do not claim certainty. A low score does not "
              + "guarantee that the screenshot is safe.";

        return sendRequest(prompt, base64Image, mimeType);
    }

    // Send the request to the configured AI service.
    private static String sendRequest(
            String prompt,
            String base64Image,
            String mimeType) throws Exception {

        String apiKey = System.getenv("AI_API_KEY");

        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException(
                    "AI_API_KEY is missing. Set it in Windows "
                  + "environment variables and restart Eclipse.");
        }

        StringBuilder parts = new StringBuilder();

        parts.append("{\"text\":\"")
             .append(escapeJson(prompt))
             .append("\"}");

        if (base64Image != null) {
            parts.append(",{\"inline_data\":{")
                 .append("\"mime_type\":\"")
                 .append(mimeType)
                 .append("\",\"data\":\"")
                 .append(base64Image)
                 .append("\"}}");
        }

        String requestBody =
                "{\"contents\":[{\"parts\":["
              + parts
              + "]}]}";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .timeout(Duration.ofSeconds(45))
                .header("x-goog-api-key", apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = CLIENT.send(
                request,
                HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException(
                    "AI service error (HTTP "
                  + response.statusCode()
                  + "). Check the model, API key, internet connection, "
                  + "and usage quota. Details: "
                  + response.body());
        }

        return extractResponseText(response.body());
    }

    // Escape text so it can safely be included in JSON.
    private static String escapeJson(String text) {

        StringBuilder escaped = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            switch (c) {
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        escaped.append(String.format("\\u%04x",
                                (int) c));
                    } else {
                        escaped.append(c);
                    }
            }
        }

        return escaped.toString();
    }

    // Extract the response text from the JSON response.
    private static String extractResponseText(String json)
            throws IOException {

        String marker = "\"text\"";
        int position = json.indexOf(marker);

        while (position >= 0) {

            int colon = json.indexOf(
                    ':', position + marker.length());

            if (colon < 0) {
                break;
            }

            int start = colon + 1;

            while (start < json.length()
                    && Character.isWhitespace(json.charAt(start))) {
                start++;
            }

            if (start >= json.length()
                    || json.charAt(start) != '"') {
                position = json.indexOf(
                        marker, position + marker.length());
                continue;
            }

            StringBuilder result = new StringBuilder();
            boolean escaped = false;

            for (int i = start + 1; i < json.length(); i++) {
                char c = json.charAt(i);

                if (escaped) {
                    switch (c) {
                        case 'n': result.append('\n'); break;
                        case 'r': result.append('\r'); break;
                        case 't': result.append('\t'); break;
                        case 'b': result.append('\b'); break;
                        case 'f': result.append('\f'); break;
                        case '"': result.append('"'); break;
                        case '\\': result.append('\\'); break;
                        case '/': result.append('/'); break;
                        case 'u':
                            if (i + 4 < json.length()) {
                                String hex = json.substring(i + 1, i + 5);
                                result.append((char)
                                        Integer.parseInt(hex, 16));
                                i += 4;
                            }
                            break;
                        default:
                            result.append(c);
                    }

                    escaped = false;

                } else if (c == '\\') {
                    escaped = true;

                } else if (c == '"') {
                    return result.toString();

                } else {
                    result.append(c);
                }
            }

            break;
        }

        throw new IOException(
                "The AI service returned no readable analysis.");
    }

    // Simple test. Run this class to test text analysis.
    public static void main(String[] args) {

        try {
            String result = analyzeText(
                    "Your bank account will be blocked. "
                  + "Send your OTP immediately to avoid suspension.");

            System.out.println("AI ANALYSIS");
            System.out.println("-----------");
            System.out.println(result);

        } catch (Exception e) {
            System.out.println("Analysis failed: " + e.getMessage());
        }
    }
}
