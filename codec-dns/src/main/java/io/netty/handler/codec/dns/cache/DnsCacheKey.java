package io.netty.handler.codec.dns.cache;

import java.util.Arrays;

public class DnsCacheKey {

	private String domain;
	private boolean single;
	private int[] types;

	public DnsCacheKey(String domain, boolean single, int... types) {
		if (domain == null || domain.isEmpty()) {
			throw new NullPointerException(
					"domain must not be null or left blank.");
		}
		if (types == null || types.length == 0) {
			throw new IllegalArgumentException("types must not be empty.");
		}
		this.domain = domain;
		this.single = single;
		this.types = types;
	}

	/**
	 * Returns the name of the domain.
	 */
	public String domain() {
		return domain;
	}

	/**
	 * Returns the types of resource record.
	 */
	public int[] types() {
		return types;
	}

	public boolean single() {
		return single;
	}

	@Override
	public int hashCode() {
		return ((domain.hashCode() * 31 + Arrays.hashCode(types)) * 31 + (single ? 1 : 0)) * 31;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o instanceof DnsCacheKey) {
			DnsCacheKey other = (DnsCacheKey) o;
			return other.single == single
					&& Arrays.equals(other.types(), types)
					&& other.domain().equals(domain);
		}
		return false;
	}

}
