package io.netty.handler.codec.dns.cache.strategy;

import io.netty.handler.codec.dns.cache.DnsCache;
import io.netty.handler.codec.dns.cache.DnsCacheBuilder;
import io.netty.handler.codec.dns.cache.DnsCacheKey;
import io.netty.handler.codec.dns.cache.DnsCacheLoader;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.ImmediateEventExecutor;

public class DnsNoCache implements DnsCache {
	
	private static class DnsNoCacheBuilder implements DnsCacheBuilder{
		private DnsCacheLoader loader;

		@Override
		public DnsCache build(DnsCacheLoader loader) {
			this.loader = loader;
			return new DnsNoCache(this);
		}
	}

	public static DnsNoCacheBuilder create(){
		return new DnsNoCacheBuilder();
	}

	private DnsCacheLoader loader;

	private DnsNoCache(DnsNoCacheBuilder builder){
		this.loader = builder.loader;
	}

	public Future<Integer> size() {
		return ImmediateEventExecutor.INSTANCE.newSucceededFuture(0);
	}

	public Future<Boolean> isEmpty() {
		return ImmediateEventExecutor.INSTANCE.newSucceededFuture(true);
	}

	public Future<Boolean> containsKey(DnsCacheKey key) {
		return ImmediateEventExecutor.INSTANCE.newSucceededFuture(false);
	}

	@SuppressWarnings("unchecked")
	public <T> Future<T> get(DnsCacheKey key) {
		if(loader != null) {
			return (Future<T>) loader.load(key);
		} else {
			return ImmediateEventExecutor.INSTANCE.newFailedFuture(new RuntimeException("dns loader is not setted."));
		}
	}

	public Future<Object> remove(DnsCacheKey key) {
		return ImmediateEventExecutor.INSTANCE.newFailedFuture(new RuntimeException("the key is not present in the cache."));
	}

	public void clear() {
		// Do nothing
	}

}
