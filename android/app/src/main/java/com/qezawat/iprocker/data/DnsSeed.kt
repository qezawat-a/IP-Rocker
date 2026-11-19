package com.qezawat.iprocker.data

import java.net.Inet6Address
import java.net.InetAddress

/**
 * Finds IPv6 edge addresses for an IPv6 scan by asking the phone's own resolver
 * for the AAAA records of hostnames served through Cloudflare. The lookup runs on
 * the device, so it sees the same DNS answers the scan's network sees.
 *
 * Only addresses inside Cloudflare's published IPv6 blocks are kept. Random
 * sampling inside those blocks almost never hits a live edge, which is why an
 * IPv6 scan probes these seeds rather than the blocks themselves.
 *
 * Blocking: call from Dispatchers.IO.
 */
object DnsSeed {

    /** Hostnames served through Cloudflare, scanned even when the user adds none. */
    val DEFAULT_DOMAINS = listOf(
        "speed.cloudflare.com",
        "cloudflare.com",
        "one.one.one.one",
        "www.cloudflare.com",
    )

    /** Cloudflare's published IPv6 blocks (cloudflare.com/ips-v6). */
    private val CLOUDFLARE_V6 = listOf(
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ).map { Prefix.parse(it) }

    /** The addresses one DNS pass found. */
    class Lookup(
        /** Unique Cloudflare IPv6 addresses. */
        val addresses: List<String>,
        /** How many addresses each domain contributed, in lookup order. */
        val perDomain: Map<String, Int>,
    )

    /** The settings to scan with, and a note to show the user. */
    class Prepared(val settings: ScanSettings, val note: String?)

    /**
     * Resolves the AAAA records of the default domains plus [extraDomains] (comma
     * or whitespace separated) and keeps the Cloudflare addresses.
     */
    fun lookup(extraDomains: String): Lookup {
        val domains = (DEFAULT_DOMAINS + parseDomains(extraDomains)).distinct()
        val found = LinkedHashSet<String>()
        val perDomain = LinkedHashMap<String, Int>()
        for (domain in domains) {
            val kept = try {
                InetAddress.getAllByName(domain)
                    .filterIsInstance<Inet6Address>()
                    .map { it.hostAddress.substringBefore('%') } // drop the scope id
                    .filter { ip -> CLOUDFLARE_V6.any { it.contains(ip) } }
                    .distinct()
            } catch (e: Exception) {
                emptyList()
            }
            perDomain[domain] = kept.size
            found += kept
        }
        return Lookup(found.toList(), perDomain)
    }

    /**
     * Builds the settings for a scan. With IPv6 off, [base] passes through
     * unchanged. With IPv6 on, the discovered addresses are the scan's whole
     * scope, together with anything the user typed in Extra CIDRs / IPs. Throws
     * when DNS finds nothing, so the caller can show the reason.
     */
    fun prepare(base: ScanSettings): Prepared {
        if (!base.ipv6) return Prepared(base, null)

        val lookup = lookup(base.extraDomains)
        if (lookup.addresses.isEmpty()) {
            throw IllegalStateException(
                "DNS gave no Cloudflare IPv6 address on this network. " +
                    "Check that IPv6 works here (test-ipv6.com), then try again.",
            )
        }

        val separator = if (base.importMode == "lines") "\n" else ","
        val merged = (listOf(base.customRanges.trim()) + lookup.addresses)
            .filter { it.isNotEmpty() }
            .joinToString(separator)

        val summary = lookup.perDomain.entries.joinToString(", ") { "${it.key} ${it.value}" }
        val note = "DNS found ${lookup.addresses.size} IPv6 addresses ($summary)."

        return Prepared(
            base.copy(
                customRanges = merged,
                onlyCustomRanges = true,
                count = lookup.addresses.size,
            ),
            note,
        )
    }

    /** Splits the user's domain field into hostnames, dropping anything that is not one. */
    private fun parseDomains(text: String): List<String> =
        text.split(Regex("[,\\s]+"))
            .map { it.trim().lowercase().removePrefix("https://").removePrefix("http://").trimEnd('/') }
            .filter { it.contains('.') && !it.contains('/') && !it.contains(':') }

    /** One IPv6 prefix, matched bit by bit. */
    private class Prefix(private val network: ByteArray, private val bits: Int) {

        fun contains(ip: String): Boolean {
            val addr = try {
                InetAddress.getByName(ip).address // a literal address, so no DNS lookup
            } catch (e: Exception) {
                return false
            }
            if (addr.size != network.size) return false
            var left = bits
            for (i in network.indices) {
                if (left <= 0) break
                val mask = if (left >= 8) 0xFF else (0xFF shl (8 - left)) and 0xFF
                if ((addr[i].toInt() and mask) != (network[i].toInt() and mask)) return false
                left -= 8
            }
            return true
        }

        companion object {
            fun parse(cidr: String): Prefix {
                val (host, len) = cidr.split('/')
                return Prefix(InetAddress.getByName(host).address, len.toInt())
            }
        }
    }
}
