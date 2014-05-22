package io.netty.handler.codec.dns.cache;

import io.netty.util.concurrent.Future;

/**
 * Used for implements caches for DNS
 */
public interface DnsCache {
	
    /**
     * Returns the amount of elements in the cache.
     *
     * @return Returns the amount of elements in the cache.
     */
	Future<Integer> size();

	/**
     * Returns <tt>true</tt> if this cache contains no value.
     *
     * @return <tt>true</tt> if this cache contains no value.
     */
	Future<Boolean> isEmpty();

	/**
     * Returns <tt>true</tt> if this cache contains  the specified
     * key.
     * @param key key whose presence in this cache is to be tested
     * @return <tt>true</tt> if this cache contains a mapping for the specified
     */
	Future<Boolean> containsKey(DnsCacheKey key);

    /**
     * Returns the value to which the specified key is mapped. If the value is
     * not present it is loaded by the DnsCacheLoader
     *
     * @param key the key whose associated value is to be returned
     * @return the value to which the specified key is mapped.
     */
    <T> Future<T> get(DnsCacheKey key);

    /**
     * Removes the mapping for a key from this cache if it is present.
     *
     * @param key key whose mapping is to be removed from the cache
     * @return the previous value associated with <tt>key</tt>, or
     *         <tt>null</tt> if there was no mapping for <tt>key</tt>.
     */
    Future<Object> remove(DnsCacheKey key);

    /**
     * Removes all the elements from this cache.
     */
    void clear();

}
