/*
 * Copyright 2014 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.jboss.netty.handler.ssl;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;
import java.util.List;

/**
 * Creates a new {@link SSLEngine}. Using its factory methods, you can let it choose the optimal {@link SSLEngine}
 * implementation available to you (the default JDK {@link SSLEngine} or the one that uses OpenSSL native library).
 */
public abstract class SslContext {

    public static Class<? extends SslContext> defaultServerContextType() {
        if (OpenSsl.isAvailable()) {
            return OpenSslContext.class;
        } else {
            return JdkSslContext.class;
        }
    }

    public static Class<? extends SslContext> defaultClientContextType() {
        return JdkSslContext.class;
    }

    public static SslContext newServerContext(String certChainPath, String keyPath) throws SSLException {
        return newServerContext(null, certChainPath, keyPath, null, null, null, 0, 0);
    }

    public static SslContext newServerInstance(
            String certChainPath, String keyPath, String keyPassword) throws SSLException {
        return newServerContext(null, certChainPath, keyPath, keyPassword, null, null, 0, 0);
    }

    public static SslContext newServerContext(
            SslBufferPool bufPool,
            String certChainPath, String keyPath, String keyPassword,
            Iterable<String> ciphers, Iterable<String> nextProtocols,
            long sessionCacheSize, long sessionTimeout) throws SSLException {

        if (OpenSsl.isAvailable()) {
            return new OpenSslContext(
                    bufPool, certChainPath, keyPath, keyPassword,
                    ciphers, nextProtocols, sessionCacheSize, sessionTimeout);
        } else {
            return new JdkSslContext(
                    bufPool, certChainPath, keyPath, keyPassword,
                    ciphers, nextProtocols, sessionCacheSize, sessionTimeout);
        }
    }

    public static SslContext newClientContext() throws SSLException {
        return newClientContext(null, null, null, null, null, 0, 0);
    }

    public static SslContext newClientContext(String certChainPath) throws SSLException {
        return newClientContext(null, certChainPath, null, null, null, 0, 0);
    }

    public static SslContext newClientContext(TrustManagerFactory trustManagerFactory) throws SSLException {
        return newClientContext(null, null, trustManagerFactory, null, null, 0, 0);
    }

    public static SslContext newClientContext(
            String certChainPath, TrustManagerFactory trustManagerFactory) throws SSLException {
        return newClientContext(null, certChainPath, trustManagerFactory, null, null, 0, 0);
    }

    public static SslContext newClientContext(
            SslBufferPool bufPool,
            String certChainPath, TrustManagerFactory trustManagerFactory,
            Iterable<String> ciphers, ApplicationProtocolSelector nextProtocolSelector,
            long sessionCacheSize, long sessionTimeout) throws SSLException {
        return new JdkSslContext(
                bufPool, certChainPath, trustManagerFactory,
                ciphers, nextProtocolSelector, sessionCacheSize, sessionTimeout);
    }

    protected SslContext() { }

    public abstract boolean isClient();

    public final boolean isServer() {
        return !isClient();
    }

    public abstract List<String> cipherSuites();

    public abstract long sessionCacheSize();

    public abstract long sessionTimeout();

    public abstract ApplicationProtocolSelector nextProtocolSelector();

    public abstract List<String> nextProtocols();

    public abstract SslBufferPool bufPool();

    public abstract SSLEngine newEngine();

    public abstract SslHandler newHandler();
}
