package com.aura.mobiledefense.domain.engines

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])

/**
 * Los parsers de OSV y URLhaus son la frontera entre una respuesta real y una alucinación:
 * estos tests fijan que una respuesta bien formada se traduce bien y que formatos corruptos,
 * truncados o hostiles no revientan ni inventan resultados.
 */
class ThreatIntelEngineTest {

    // ── parseOsvTarget ─────────────────────────────────────────────────────────────────────

    @Test
    fun `osv target parses ecosystem, name and version`() {
        val t = ThreatIntelParsers.parseOsvTarget("PyPI:django:3.2.1")!!
        assertEquals("PyPI", t.ecosystem)
        assertEquals("django", t.name)
        assertEquals("3.2.1", t.version)
    }

    @Test
    fun `osv target handles maven coordinates with colons`() {
        val t = ThreatIntelParsers.parseOsvTarget("Maven:org.apache.struts:struts2-core:2.5.10")!!
        assertEquals("Maven", t.ecosystem)
        assertEquals("org.apache.struts:struts2-core", t.name)
        assertEquals("2.5.10", t.version)
    }

    @Test
    fun `osv target accepts go module paths and uppercase ecosystem`() {
        val t = ThreatIntelParsers.parseOsvTarget("GO:golang.org/x/text:v0.3.0")!!
        assertEquals("Go", t.ecosystem)
        assertEquals("golang.org/x/text", t.name)
        assertEquals("v0.3.0", t.version)
    }

    @Test
    fun `osv target rejects garbage`() {
        assertNull(ThreatIntelParsers.parseOsvTarget(""))
        assertNull(ThreatIntelParsers.parseOsvTarget("django:3.2.1"))
        assertNull(ThreatIntelParsers.parseOsvTarget("PyPI:django:"))
        assertNull(ThreatIntelParsers.parseOsvTarget("unknownco:pkg:1.0"))
        assertNull(ThreatIntelParsers.parseOsvTarget("PyPI::1.0"))
    }

    // ── extractHost ───────────────────────────────────────────────────────────────────────

    @Test
    fun `host extraction from urls and bare hosts`() {
        assertEquals("evil.example", ThreatIntelParsers.extractHost("https://evil.example/a/b?c=d"))
        assertEquals("evil.example", ThreatIntelParsers.extractHost("http://evil.example:8080/x"))
        assertEquals("evil.example", ThreatIntelParsers.extractHost("evil.example"))
        assertEquals("evil.example", ThreatIntelParsers.extractHost("evil.example/path"))
        assertEquals("a.b.c.evil.example", ThreatIntelParsers.extractHost("https://a.b.c.evil.example/"))
    }

    @Test
    fun `host extraction rejects non-hosts`() {
        assertNull(ThreatIntelParsers.extractHost(""))
        assertNull(ThreatIntelParsers.extractHost("not a host!!"))
        assertNull(ThreatIntelParsers.extractHost("https://"))
        assertNull(ThreatIntelParsers.extractHost("localhost"))
    }

    // ── parseOsvResponse ──────────────────────────────────────────────────────────────────

    @Test
    fun `osv response with vulnerabilities parses ids, aliases and counts`() {
        val body = """
        {
          "vulns": [
            {
              "id": "GHSA-xxxx-yyyy-zzzz",
              "aliases": ["CVE-2023-1234", "PYSEC-2023-5"],
              "summary": "SQL injection in django admin"
            },
            {
              "id": "CVE-2024-9999",
              "summary": "Denial of service"
            }
          ]
        }
        """.trimIndent()
        val parsed = ThreatIntelParsers.parseOsvResponse(body)
        assertEquals(2, parsed.total)
        assertEquals(2, parsed.entries.size)
        assertTrue(parsed.entries[0].contains("GHSA-xxxx-yyyy-zzzz"))
        assertTrue(parsed.entries[0].contains("CVE-2023-1234"))
        assertTrue(parsed.entries[1].contains("CVE-2024-9999"))
    }

    @Test
    fun `osv empty or missing vulns means zero, not an error`() {
        assertEquals(0, ThreatIntelParsers.parseOsvResponse("""{"vulns": []}""").total)
        assertEquals(0, ThreatIntelParsers.parseOsvResponse("""{}""").total)
    }

    // ── parseUrlhausResponse ──────────────────────────────────────────────────────────────

    @Test
    fun `urlhaus ok response parses count and entries`() {
        val body = """
        {
          "query_status": "ok",
          "urls": [
            {"id": "123", "url": "https://evil.example/payload.exe", "threat": "malware_download", "date_added": "2026-11-20 10:00:00", "url_status": "online"},
            {"id": "124", "url": "https://evil.example/second", "threat": "malware_download", "date_added": "2026-11-21 11:00:00"}
          ]
        }
        """.trimIndent()
        val parsed = ThreatIntelParsers.parseUrlhausResponse(body)
        assertEquals("ok", parsed.queryStatus)
        assertEquals(2, parsed.urlCount)
        assertEquals(2, parsed.entries.size)
        assertTrue(parsed.entries[0].contains("evil.example"))
    }

    @Test
    fun `urlhaus no results stays honest zero`() {
        val parsed = ThreatIntelParsers.parseUrlhausResponse("""{"query_status": "no_results"}""")
        assertEquals("no_results", parsed.queryStatus)
        assertEquals(0, parsed.urlCount)
        assertEquals(0, parsed.entries.size)
    }

    @Test
    fun `urlhaus truncated entry list keeps the real total`() {
        val urls = (1..25).joinToString(",") {
            """{"id": "$it", "url": "https://evil.example/$it", "threat": "malware_download", "date_added": "2026-11-20"}"""
        }
        val parsed = ThreatIntelParsers.parseUrlhausResponse("""{"query_status": "ok", "urls": [$urls]}""")
        assertEquals(25, parsed.urlCount)
        assertEquals(10, parsed.entries.size)
    }
}
