
package FRAMES;

import java.net.IDN;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

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

    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^(?:\\d{1,3}\\.){3}\\d{1,3}$");

    private static final Pattern SHORTENER_PATTERN = Pattern.compile(
            "(?i)(?:bit\\.ly|tinyurl\\.com|t\\.co|cutt\\.ly|rb\\.gy"
            + "|is\\.gd|shorturl\\.at|rebrand\\.ly|ow\\.ly"
            + "|buff\\.ly|lnkd\\.in|soo\\.gd|s\\.id)$");

    private static final Pattern HEX_IP_PATTERN = Pattern.compile(
            "(?i)^0x[0-9a-f]+$");

    private static final String[] SUSPICIOUS_TERMS = {
            "verify", "verification", "login", "signin",
            "password", "credential", "wallet", "free-gift",
            "urgent", "secure-account", "account-verify",
            "kyc", "claim-prize", "banking-update",
            "payment-confirm", "unlock-account",
            "reset-password", "confirm-identity"
    };

    private static final String[] BRAND_NAMES = {
            "google", "microsoft", "apple", "amazon",
            "paypal", "netflix", "facebook", "instagram",
            "whatsapp", "sbi", "hdfc", "icici",
            "axisbank", "phonepe", "paytm", "googlepay"
    };

    public static AnalysisResult analyze(String input) {

        Set<String> reasons = new LinkedHashSet<>();
        int risk = 0;

        if (input == null || input.trim().isEmpty()) {
            ArrayList<String> invalidReasons = new ArrayList<>();
            invalidReasons.add("Please enter a website URL.");

            return new AnalysisResult(
                    0, "INVALID INPUT", invalidReasons);
        }

        String original = input.trim();

        // Reject whitespace within a URL.
        if (original.matches(".*\\s+.*")) {
            reasons.add(
                    "The input contains whitespace, which may indicate "
                    + "a malformed or incorrectly copied URL.");

            return new AnalysisResult(
                    0, "INVALID INPUT",
                    new ArrayList<>(reasons));
        }

        // Add HTTPS only when no scheme was supplied.
        String url = original;

        if (!url.matches("(?i)^[a-z][a-z0-9+.-]*:.*")) {
            url = "https://" + url;
        }

        URI uri;

        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException ex) {
            reasons.add("The URL format is invalid.");

            return new AnalysisResult(
                    0, "INVALID INPUT",
                    new ArrayList<>(reasons));
        }

        String scheme = uri.getScheme();

        if (scheme == null
                || (!scheme.equalsIgnoreCase("http")
                && !scheme.equalsIgnoreCase("https"))) {

            reasons.add(
                    "The URL does not use a supported HTTP or HTTPS scheme.");

            return new AnalysisResult(
                    0, "INVALID INPUT",
                    new ArrayList<>(reasons));
        }

        String host = uri.getHost();

        // URI.getHost() may return null for internationalized
        // domains or certain malformed authorities.
        if (host == null || host.isEmpty()) {
            reasons.add(
                    "A valid website hostname could not be identified.");

            return new AnalysisResult(
                    0, "INVALID INPUT",
                    new ArrayList<>(reasons));
        }

        host = host.toLowerCase(Locale.ROOT);

        // Remove a trailing dot from the hostname.
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }

        String asciiHost;

        try {
            asciiHost = IDN.toASCII(host)
                    .toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException ex) {
            reasons.add(
                    "The hostname contains invalid internationalized "
                    + "domain characters.");

            return new AnalysisResult(
                    0, "INVALID INPUT",
                    new ArrayList<>(reasons));
        }

        // 1. HTTPS / HTTP.
        if ("http".equalsIgnoreCase(scheme)) {
            risk += 10;
            reasons.add(
                    "The website uses HTTP rather than HTTPS. "
                    + "The connection may lack encryption.");
        }

        // 2. IP-address hostnames.
        if (IPV4_PATTERN.matcher(asciiHost).matches()) {

            if (isValidIpv4(asciiHost)) {
                risk += 25;
                reasons.add(
                        "The website uses an IPv4 address instead of "
                        + "a conventional domain name.");
            }
        }

        // 3. URL length.
        if (url.length() > 150) {
            risk += 10;
            reasons.add(
                    "The URL is unusually long and may hide "
                    + "important destination details.");
        }

        // 4. URL shorteners.
        String registrableCandidate = getLastTwoLabels(asciiHost);

        if (SHORTENER_PATTERN.matcher(registrableCandidate).matches()) {
            risk += 15;
            reasons.add(
                    "The hostname belongs to a known URL-shortening "
                    + "service, which can conceal the final destination.");
        }

        // 5. User information in URL authority, such as example.com@host.
        String authority = uri.getRawAuthority();

        if (authority != null && authority.contains("@")) {
            risk += 25;
            reasons.add(
                    "The URL contains an @ symbol in its authority. "
                    + "This can be used to disguise the actual hostname.");
        }

        // 6. Non-standard ports.
        int port = uri.getPort();

        if (port != -1
                && port != 80
                && port != 443) {

            risk += 10;
            reasons.add(
                    "The website uses a non-standard HTTP/HTTPS port.");
        }

        // 7. Suspicious terms in hostname or path.
        String lowerUrl = url.toLowerCase(Locale.ROOT);
        boolean suspiciousTermFound = false;

        for (String term : SUSPICIOUS_TERMS) {

            if (containsTerm(asciiHost, term)
                    || containsTerm(uri.getRawPath() == null
                            ? "" : uri.getRawPath().toLowerCase(Locale.ROOT),
                            term)) {

                suspiciousTermFound = true;

                reasons.add(
                        "The URL contains a potentially suspicious term: "
                        + term + ".");

                risk += 8;

                // Avoid repeatedly adding points for many words.
                if (risk > 100) {
                    risk = 100;
                }
            }
        }

        if (suspiciousTermFound) {
            // The individual term rules already contributed points.
        }

        // 8. Excessive subdomains.
        String[] labels = asciiHost.split("\\.");

        if (labels.length >= 5) {
            risk += 15;
            reasons.add(
                    "The hostname contains many domain levels. "
                    + "Check whether the actual registered domain "
                    + "matches the claimed organization.");
        } else if (labels.length == 4) {
            risk += 5;
            reasons.add(
                    "The hostname contains several domain levels. "
                    + "Inspect the registered domain carefully.");
        }

        // 9. Punycode / internationalized hostname.
        if (asciiHost.contains("xn--")) {
            risk += 15;
            reasons.add(
                    "The hostname contains internationalized-domain "
                    + "encoding. Inspect it carefully for lookalike "
                    + "characters.");
        }

        // 10. Encoded or unusual URL characters.
        String raw = uri.getRawPath();

        if (raw != null && raw.matches("(?i).*(%[0-9a-f]{2}).*")) {
            risk += 5;
            reasons.add(
                    "The URL path contains percent-encoded characters. "
                    + "These are legitimate in many URLs but can obscure "
                    + "the visible path.");
        }

        if (url.contains("\\\\")) {
            risk += 15;
            reasons.add(
                    "The URL contains backslash characters that may "
                    + "make its interpretation confusing.");
        }

        // 11. Brand-name lookalike heuristics.
        // This detects suspicious placement, not actual brand ownership.
        String[] hostLabels = asciiHost.split("\\.");
        String mainLabel = hostLabels.length >= 2
                ? hostLabels[hostLabels.length - 2]
                : asciiHost;

        for (String brand : BRAND_NAMES) {

            if (mainLabel.contains(brand)
                    && !mainLabel.equals(brand)
                    && looksLikeBrandVariant(mainLabel, brand)) {

                risk += 15;
                reasons.add(
                        "The registered-domain label resembles the "
                        + brand + " brand name but is not an exact match.");

                break;
            }
        }

        // 12. Risky redirect-style query parameters.
        String query = uri.getRawQuery();

        if (query != null
                && query.matches(
                "(?i).*(redirect=|redirect_url=|return=|"
                + "returnurl=|continue=|next=|url=).*")) {

            risk += 5;
            reasons.add(
                    "The URL contains a redirect-style query parameter. "
                    + "This is not inherently malicious but merits "
                    + "inspection.");
        }

        // 13. Combine independent indicators.
        int indicatorCount = reasons.size();

        if (indicatorCount >= 4) {
            risk += 10;
            reasons.add(
                    "Several independent URL warning signs were detected "
                    + "together.");
        }

        // Keep score within 0–100.
        risk = Math.min(risk, 100);

        String classification;

        if (risk >= 60) {
            classification = "SUSPICIOUS";
        } else if (risk >= 25) {
            classification = "NEEDS REVIEW";
        } else {
            classification = "NO OBVIOUS WARNING SIGNS";
        }

        if (reasons.isEmpty()) {
            reasons.add(
                    "No significant warning signs were detected by "
                    + "these URL rules. This does not guarantee that "
                    + "the website is safe.");
        }

        return new AnalysisResult(
                risk,
                classification,
                new ArrayList<>(reasons));
    }

    private static boolean isValidIpv4(String host) {

        String[] parts = host.split("\\.");

        for (String part : parts) {
            try {
                int value = Integer.parseInt(part);

                if (value < 0 || value > 255) {
                    return false;
                }
            } catch (NumberFormatException ex) {
                return false;
            }
        }

        return true;
    }

    private static boolean containsTerm(
            String text, String term) {

        return text != null
                && text.toLowerCase(Locale.ROOT).contains(term);
    }

    private static String getLastTwoLabels(String host) {

        String[] labels = host.split("\\.");

        if (labels.length < 2) {
            return host;
        }

        return labels[labels.length - 2]
                + "." + labels[labels.length - 1];
    }

    private static boolean looksLikeBrandVariant(
            String domainLabel, String brand) {

        // Detect common additions around a brand name.
        return domainLabel.startsWith(brand)
                || domainLabel.endsWith(brand)
                || domainLabel.contains(brand + "-")
                || domainLabel.contains("-" + brand)
                || domainLabel.matches(".*\\d.*");
    }
}
