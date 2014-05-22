package io.netty.handler.codec.dns.cache;

import io.netty.util.concurrent.Future;

public interface DnsCacheLoader {

	Future<Object> load(DnsCacheKey key);
	
}
