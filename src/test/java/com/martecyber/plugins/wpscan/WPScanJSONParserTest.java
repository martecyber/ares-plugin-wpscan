package com.martecyber.plugins.wpscan;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link WPScanJSONParser}: target-URL → WEB_APPLICATION resolution with default-port
 *  suppression, the WordPress-core/plugin/theme vulnerability fan-out (each keyed to the same
 *  resolved asset), CVSS string-to-severity bucketing, and interesting-findings detections. */
class WPScanJSONParserTest {

    private final WPScanJSONParser parser = new WPScanJSONParser();

    private ParseResult parse(String json) throws Exception {
        return parser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateRequiresTargetUrlPlusVulnerabilitiesOrInterestingFindings() {
        assertTrue(parser.validate("{\"target_url\":\"http://a\",\"vulnerabilities\":[]}".getBytes(StandardCharsets.UTF_8)));
        assertTrue(parser.validate("{\"target_url\":\"http://a\",\"interesting_findings\":[]}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("{\"target_url\":\"http://a\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void resolvesTargetUrlToAWebApplicationSuppressingTheDefaultPort() throws Exception {
        ParseResult result = parse("{\"target_url\":\"https://example.com/\"}");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_APPLICATION) && a.getIdentifier().equals("https://example.com")));
    }

    @Test
    void resolvesTargetUrlKeepingANonDefaultPort() throws Exception {
        ParseResult result = parse("{\"target_url\":\"http://example.com:8080/\"}");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("http://example.com:8080")));
    }

    @Test
    void wordpressVersionEmitsAnInfoDetectionAndItsOwnVulnerabilities() throws Exception {
        ParseResult result = parse("""
            {"target_url":"http://example.com",
             "version":{"number":"6.4","vulnerabilities":[
               {"title":"WP Core XSS","cvss":"7.5","references":{"cve":["2024-0001"]}}
             ]}}
            """);

        assertTrue(result.getDetections().stream().anyMatch(d -> "WordPress 6.4 detected".equals(d.getTitle()) && "info".equals(d.getSeverity())));
        ParsedDetection vuln = result.getDetections().stream().filter(d -> "WP Core XSS".equals(d.getTitle())).findFirst().orElseThrow();
        assertEquals("high", vuln.getSeverity());
        assertTrue(vuln.getDescription().contains("Component: WordPress Core 6.4"));
        assertTrue(vuln.getDescription().contains("CVE: 2024-0001"));
        assertEquals("http://example.com", vuln.getAssetIdentifier());
    }

    @Test
    void pluginAndThemeVulnerabilitiesAreLabeledWithNameAndVersion() throws Exception {
        ParseResult result = parse("""
            {"target_url":"http://example.com",
             "plugins":{"contact-form-7":{"version":"5.1","vulnerabilities":[{"title":"CF7 SQLi","cvss":"9.8"}]}},
             "themes":{"twentytwenty":{"version":"1.0","vulnerabilities":[{"title":"Theme XSS","cvss":"6.1"}]}}}
            """);

        ParsedDetection pluginVuln = result.getDetections().stream().filter(d -> "CF7 SQLi".equals(d.getTitle())).findFirst().orElseThrow();
        assertTrue(pluginVuln.getDescription().contains("Component: Plugin: contact-form-7 5.1"));
        assertEquals("critical", pluginVuln.getSeverity());

        ParsedDetection themeVuln = result.getDetections().stream().filter(d -> "Theme XSS".equals(d.getTitle())).findFirst().orElseThrow();
        assertTrue(themeVuln.getDescription().contains("Component: Theme: twentytwenty 1.0"));
        assertEquals("medium", themeVuln.getSeverity());
    }

    @Test
    void pluginWithoutAVersionFallsBackToUnknown() throws Exception {
        ParseResult result = parse("""
            {"target_url":"http://example.com",
             "plugins":{"mystery-plugin":{"vulnerabilities":[{"title":"Mystery bug"}]}}}
            """);
        assertTrue(result.getDetections().get(0).getDescription().contains("Component: Plugin: mystery-plugin unknown"));
    }

    @Test
    void missingCvssDefaultsToMediumSeverity() throws Exception {
        ParseResult result = parse("""
            {"target_url":"http://example.com","version":{"number":"6.4","vulnerabilities":[{"title":"Unscored issue"}]}}
            """);
        ParsedDetection vuln = result.getDetections().stream().filter(d -> "Unscored issue".equals(d.getTitle())).findFirst().orElseThrow();
        assertEquals("medium", vuln.getSeverity());
    }

    @Test
    void interestingFindingsBecomeInfoDetectionsWithTheirOwnUrl() throws Exception {
        ParseResult result = parse("""
            {"target_url":"http://example.com",
             "interesting_findings":[{"type":"headers","url":"http://example.com/wp-login.php"}]}
            """);
        ParsedDetection d = result.getDetections().get(0);
        assertEquals("Interesting finding: headers", d.getTitle());
        assertEquals("info", d.getSeverity());
        assertEquals("Found at: http://example.com/wp-login.php", d.getDescription());
    }

    @Test
    void vulnerabilityWithoutATitleFallsBackToUnknownVulnerability() throws Exception {
        ParseResult result = parse("""
            {"target_url":"http://example.com","version":{"number":"6.4","vulnerabilities":[{"cvss":"5.0"}]}}
            """);
        assertTrue(result.getDetections().stream().anyMatch(d -> "Unknown vulnerability".equals(d.getTitle())));
    }
}
