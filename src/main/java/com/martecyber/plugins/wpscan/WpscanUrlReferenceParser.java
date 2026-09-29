package com.martecyber.plugins.wpscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.detections.DetectionUrlReferenceParser;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Set;

/** Reads WPScan's {@code references.url[]} — the one structured field WPScan embeds for
 *  documentation/vulnerability-reference URLs. See DetectionUrlReferenceParser's own doc
 *  (ares-core) for why this is scoped to one known field path rather than regex-scanning the
 *  whole raw payload. */
@Component
public class WpscanUrlReferenceParser implements DetectionUrlReferenceParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId() { return "wpscan"; }

    @Override
    public Set<String> extractUrls(String rawJson) {
        Set<String> out = new LinkedHashSet<>();
        try {
            JsonNode root = MAPPER.readTree(rawJson);
            JsonNode references = root.get("references");
            if (references == null) return out;
            JsonNode urls = references.get("url");
            if (urls == null || !urls.isArray()) return out;
            urls.forEach(n -> {
                String v = n.asText(null);
                if (v != null && (v.startsWith("http://") || v.startsWith("https://"))) out.add(v.trim());
            });
        } catch (Exception ignored) {
            // Malformed rawData — treat as "nothing found", never fail the import over this.
        }
        return out;
    }
}
