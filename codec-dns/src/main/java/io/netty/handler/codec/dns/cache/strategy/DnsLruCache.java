package io.netty.handler.codec.dns.cache.strategy;

import java.util.Collections;
import java.util.Map;

import io.netty.handler.codec.dns.cache.DnsCache;
import io.netty.handler.codec.dns.cache.DnsCacheBuilder;
import io.netty.handler.codec.dns.cache.DnsCacheKey;
import io.netty.handler.codec.dns.cache.DnsCacheLoader;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import io.netty.util.concurrent.ImmediateEventExecutor;

import org.apache.commons.collections.map.LRUMap;

/**
 * LRU cache implementation for DNS. This implementation is only a wrapper of {@link LRUMap}
 */
public class DnsLruCache implements DnsCache {

	private static class DnsLruCacheBuilder implements DnsCacheBuilder{
		private DnsCacheLoader loader;
		private int maxSize;

		public DnsLruCacheBuilder maxSize(int maxSize){
			this.maxSize = maxSize;
			return this;
		}

		@Override
		public DnsCache build(DnsCacheLoader loader) {
			this.loader = loader;
			return new DnsLruCache(this);
		}
	}

	public static DnsLruCacheBuilder create(){
		return new DnsLruCacheBuilder();
	}

	private Map<Object, Object> lru;
	private DnsCacheLoader loader;

    /**
     * Constructs a LRU cache.
     *
     * @param maxSize
     *            Max size.
     */
	@SuppressWarnings("unchecked")
	private DnsLruCache(DnsLruCacheBuilder builder) {
		lru = Collections.synchronizedMap(new LRUMap(builder.maxSize));
		loader = builder.loader;
	}

	public Future<Boolean> containsKey(DnsCacheKey key) {
		return ImmediateEventExecutor.INSTANCE.newSucceededFuture(lru.containsKey(key));
	}

	@SuppressWarnings("unchecked")
	public <T> Future<T> get(DnsCacheKey key) {
		Object storedValue = lru.get(key);

		if(storedValue != null){
			return ImmediateEventExecutor.INSTANCE.newSucceededFuture((T)storedValue);
		} else if(loader != null) {
			return (Future<T>)put(key, loader.load(key));
		} else {
			return ImmediateEventExecutor.INSTANCE.newFailedFuture(new RuntimeException("dns loader is not setted."));
		}
	}

	private Future<Object> put(final DnsCacheKey key, Future<Object> value) {
		value.addListener(new GenericFutureListener<Future<Object>>() {
			@Override
			public void operationComplete(Future<Object> future)
					throws Exception {
				if(future.isSuccess()){
					lru.put(key, future.getNow());
				}
			}
		});
		return value;
	}

	public Future<Object> remove(DnsCacheKey key) {
		return ImmediateEventExecutor.INSTANCE.newSucceededFuture(lru.remove(key));
	}

	public Future<Integer> size() {
		return ImmediateEventExecutor.INSTANCE.newSucceededFuture(lru.size());
	}

	public Future<Boolean> isEmpty() {
		return ImmediateEventExecutor.INSTANCE.newSucceededFuture(lru.isEmpty());
	}

	public void clear() {
		lru.clear();
	}
}
