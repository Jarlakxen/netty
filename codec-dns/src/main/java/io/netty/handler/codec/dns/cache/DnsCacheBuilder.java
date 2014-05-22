package io.netty.handler.codec.dns.cache;

/**
 * Used for construct a DnsCache
 */
public interface DnsCacheBuilder {

    /**
     * Create a cache instance.
     * @param loader the loader function, that can get the data from the DNS
     *  when the data is not present in the cache.
     * @return a DnsCache instance
     */
	DnsCache build(DnsCacheLoader loader);
	
}
