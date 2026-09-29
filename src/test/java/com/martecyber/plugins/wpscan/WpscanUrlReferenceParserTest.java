package com.martecyber.plugins.wpscan;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class WpscanUrlReferenceParserTest {

    private final WpscanUrlReferenceParser parser = new WpscanUrlReferenceParser();

    @Test
    void toolIdIsWpscan() {
        assertEquals("wpscan", parser.getToolId());
    }

    @Test
    void extractsUrlsFromReferencesUrlArray() {
        String raw = """
            {"references":{"url":["https://wpscan.com/vulnerability/abc123","https://cve.example.com/CVE-2024-1"]}}""";
        Set<String> urls = parser.extractUrls(raw);
        assertEquals(Set.of("https://wpscan.com/vulnerability/abc123", "https://cve.example.com/CVE-2024-1"), urls);
    }

    @Test
    void ignoresNonHttpEntries() {
        String raw = """
            {"references":{"url":["not-a-url","https://ok.example.com"]}}""";
        assertEquals(Set.of("https://ok.example.com"), parser.extractUrls(raw));
    }

    @Test
    void returnsEmptySetWhenReferencesOrUrlIsMissing() {
        assertTrue(parser.extractUrls("{}").isEmpty());
        assertTrue(parser.extractUrls("""
            {"references":{}}""").isEmpty());
    }

    @Test
    void returnsEmptySetForMalformedJsonRatherThanThrowing() {
        assertTrue(parser.extractUrls("not json at all").isEmpty());
    }
}
