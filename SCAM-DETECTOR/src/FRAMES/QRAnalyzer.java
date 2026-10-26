
package FRAMES;

import java.awt.image.BufferedImage;
import java.io.File;
import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.EnumMap;

import javax.imageio.ImageIO;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

public class QRAnalyzer {

    public static String scanQR(File file) throws Exception {

        BufferedImage image = ImageIO.read(file);

        if (image == null) {
            return "ERROR: Cannot read this image. Use PNG or JPG.";
        }

        LuminanceSource source =
                new BufferedImageLuminanceSource(image);

        BinaryBitmap bitmap = new BinaryBitmap(
                new HybridBinarizer(source));

        Map<DecodeHintType, Object> hints =
                new EnumMap<>(DecodeHintType.class);

        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);

        Result result;

        try {
            result = new MultiFormatReader().decode(bitmap, hints);
        } catch (NotFoundException e) {
            return "NO QR CODE FOUND\n\n"
                    + "Try a clearer image with the entire QR code visible.";
        }

        String content = result.getText();
        String lower = content.toLowerCase(Locale.ROOT);

        StringBuilder report = new StringBuilder();

        report.append("QR CODE ANALYSIS\n");
        report.append("================\n\n");
        report.append("Decoded content:\n");
        report.append(content);
        report.append("\n\n");

        boolean suspicious = false;

        if (lower.contains("verify your account")
                || lower.contains("password")
                || lower.contains("otp")
                || lower.contains("account suspended")
                || lower.contains("claim your prize")) {

            suspicious = true;
            report.append(
                    "Warning: Content contains common scam-related terms.\n");
        }

        if (lower.startsWith("http://")
                || lower.startsWith("https://")) {

            try {
                URI uri = URI.create(content);
                String host = uri.getHost();

                if (host == null || host.isEmpty()) {
                    suspicious = true;
                    report.append("Warning: URL host is invalid.\n");
                } else {
                    report.append("Detected URL host: ")
                            .append(host)
                            .append("\n");

                    if (host.matches("\\d{1,3}(\\.\\d{1,3}){3}")
                            || host.toLowerCase(Locale.ROOT).startsWith("xn--")) {

                        suspicious = true;
                        report.append(
                                "Warning: URL has an unusual host pattern.\n");
                    }
                }

                if (lower.startsWith("http://")) {
                    suspicious = true;
                    report.append(
                            "Warning: URL uses unencrypted HTTP.\n");
                }

            } catch (IllegalArgumentException e) {
                suspicious = true;
                report.append("Warning: URL format is invalid.\n");
            }

        } else if (lower.startsWith("upi://")) {
            report.append(
                    "Payment QR detected. Verify the recipient and amount "
                    + "before paying.\n");
        }

        report.append("\nRESULT: ");

        if (suspicious) {
            report.append("SUSPICIOUS — CHECK CAREFULLY\n");
        } else {
            report.append("NO OBVIOUS WARNING SIGNS DETECTED\n");
        }

        report.append(
                "\nThis is a basic rule-based check, not a guarantee "
                + "that the QR code is safe.");

        return report.toString();
    }
}
