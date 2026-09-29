package com.martecyber.plugins.wpscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class WPScanJSONParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern HOST_PATTERN = Pattern.compile("^(?:https?://)?([^/]+)");

    @Override public String getToolId() { return "wpscan"; }
    @Override public String getDisplayName() { return "WPScan JSON"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".json"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8);
        return s.contains("\"target_url\"") && (s.contains("\"vulnerabilities\"") || s.contains("\"interesting_findings\""));
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        JsonNode root = MAPPER.readTree(content);

        String targetUrl = text(root, "target_url");
        String resolvedAsset = null;
        if (targetUrl != null) {
            // WordPress always runs on an HTTP/HTTPS endpoint → web_application
            try {
                java.net.URI uri = new java.net.URI(targetUrl);
                String scheme = uri.getScheme() != null ? uri.getScheme() : "http";
                String host   = uri.getHost();
                int port      = uri.getPort();
                boolean defaultPort = ("https".equals(scheme) && port == 443)
                    || ("http".equals(scheme) && port == 80) || port == -1;
                resolvedAsset = scheme + "://" + host + (defaultPort ? "" : ":" + port);
            } catch (Exception e) {
                Matcher m = HOST_PATTERN.matcher(targetUrl);
                if (m.find()) resolvedAsset = targetUrl;
            }
            if (resolvedAsset != null) {
                // "url" intentionally not stored here — it duplicates the asset's own identifier.
                result.addAsset(new ParsedAsset(resolvedAsset, AssetType.WEB_APPLICATION, Map.of()));
            }
        }
        final String assetIdentifier = resolvedAsset;

        // WordPress version info
        JsonNode wpVersion = root.get("version");
        if (wpVersion != null && wpVersion.has("number")) {
            String ver = wpVersion.get("number").asText();
            String raw;
            try { raw = MAPPER.writeValueAsString(wpVersion); } catch (Exception e) { raw = "{}"; }
            result.addDetection(new ParsedDetection(
                "WordPress " + ver + " detected",
                "info",
                "WordPress version " + ver + " is running on the target.",
                assetIdentifier, "wpscan-wp-version-" + ver.replace(".", "-"), raw
            ));
            // Vulnerabilities for WP core
            processVulnerabilities(wpVersion, "WordPress Core " + ver, assetIdentifier, result);
        }

        // Plugins
        JsonNode plugins = root.get("plugins");
        if (plugins != null) {
            plugins.fields().forEachRemaining(entry -> {
                String pluginName = entry.getKey();
                JsonNode plugin = entry.getValue();
                String version = text(plugin, "version") != null ? text(plugin, "version") : "unknown";
                processVulnerabilities(plugin, "Plugin: " + pluginName + " " + version, assetIdentifier, result);
            });
        }

        // Themes
        JsonNode themes = root.get("themes");
        if (themes != null) {
            themes.fields().forEachRemaining(entry -> {
                String themeName = entry.getKey();
                JsonNode theme = entry.getValue();
                String themeVer = text(theme, "version") != null ? text(theme, "version") : "unknown";
                processVulnerabilities(theme, "Theme: " + themeName + " " + themeVer, assetIdentifier, result);
            });
        }

        // Interesting findings (non-vulnerability)
        JsonNode findings = root.get("interesting_findings");
        if (findings != null && findings.isArray()) {
            for (JsonNode f : findings) {
                String type = text(f, "type");
                String url = text(f, "url");
                String raw;
                try { raw = MAPPER.writeValueAsString(f); } catch (Exception e) { raw = "{}"; }
                result.addDetection(new ParsedDetection(
                    "Interesting finding: " + (type != null ? type : "unknown"),
                    "info",
                    url != null ? "Found at: " + url : "",
                    assetIdentifier,
                    "wpscan-finding-" + (type != null ? type.toLowerCase().replaceAll("[^a-z0-9]", "-") : "unknown"),
                    raw
                ));
            }
        }

        return result;
    }

    private void processVulnerabilities(JsonNode node, String context, String assetIdentifier, ParseResult result) {
        JsonNode vulns = node.get("vulnerabilities");
        if (vulns == null || !vulns.isArray()) return;
        for (JsonNode vuln : vulns) {
            String title = text(vuln, "title");
            if (title == null) title = "Unknown vulnerability";
            String cvss = text(vuln, "cvss");
            String severity = cvssToSeverity(cvss);

            StringBuilder desc = new StringBuilder();
            desc.append("Component: ").append(context).append("\n");
            if (cvss != null) desc.append("CVSS: ").append(cvss).append("\n");

            JsonNode refs = vuln.get("references");
            if (refs != null) {
                if (refs.has("cve")) refs.get("cve").forEach(c -> desc.append("CVE: ").append(c.asText()).append("\n"));
                if (refs.has("url")) refs.get("url").forEach(u -> desc.append("URL: ").append(u.asText()).append("\n"));
            }

            String raw;
            try { raw = MAPPER.writeValueAsString(vuln); } catch (Exception e) { raw = "{}"; }
            String templateId = "wpscan-" + title.toLowerCase().replaceAll("[^a-z0-9]+", "-");
            if (templateId.length() > 200) templateId = templateId.substring(0, 200);

            result.addDetection(new ParsedDetection(title, severity, desc.toString().trim(), assetIdentifier, templateId, raw));
        }
    }

    private String cvssToSeverity(String cvss) {
        if (cvss == null) return "medium";
        try {
            double score = Double.parseDouble(cvss);
            if (score >= 9.0) return "critical";
            if (score >= 7.0) return "high";
            if (score >= 4.0) return "medium";
            if (score > 0) return "low";
        } catch (NumberFormatException ignored) {}
        return "medium";
    }

    private static String text(JsonNode node, String field) {
        JsonNode n = node.get(field);
        return (n != null && !n.isNull() && n.isTextual() && !n.asText().isBlank()) ? n.asText() : null;
    }
}
