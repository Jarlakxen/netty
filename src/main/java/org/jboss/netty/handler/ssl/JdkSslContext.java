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

import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public abstract class JdkSslContext extends SslContext {

    private static final InternalLogger logger = InternalLoggerFactory.getInstance(JdkSslContext.class);

    static final List<String> DEFAULT_CIPHERS;
    static final String PROTOCOL = "TLS";

    static {
        SSLContext context;
        try {
            context = SSLContext.getInstance(PROTOCOL);
            context.init(null, null, null);
        } catch (Exception e) {
            throw new Error("failed to initialize the default SSL context", e);
        }

        String[] supportedCiphers = context.getSocketFactory().getSupportedCipherSuites();
        List<String> ciphers = new ArrayList<String>();
        // XXX: Make sure to sync this list with OpenSslEngineFactory.
        addCipher(supportedCiphers, ciphers, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
        addCipher(supportedCiphers, ciphers, "TLS_ECDHE_RSA_WITH_RC4_128_SHA");
        addCipher(supportedCiphers, ciphers, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        addCipher(supportedCiphers, ciphers, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        addCipher(supportedCiphers, ciphers, "TLS_RSA_WITH_AES_128_CBC_SHA256");
        addCipher(supportedCiphers, ciphers, "SSL_RSA_WITH_RC4_128_SHA");
        addCipher(supportedCiphers, ciphers, "SSL_RSA_WITH_RC4_128_MD5");
        addCipher(supportedCiphers, ciphers, "TLS_RSA_WITH_AES_128_CBC_SHA");
        addCipher(supportedCiphers, ciphers, "TLS_RSA_WITH_AES_256_CBC_SHA");
        addCipher(supportedCiphers, ciphers, "SSL_RSA_WITH_DES_CBC_SHA");
        DEFAULT_CIPHERS = Collections.unmodifiableList(ciphers);

        if (logger.isDebugEnabled()) {
            logger.debug("Default cipher suite (JDK): " + ciphers);
        }
    }

    private static void addCipher(String[] supportedCiphers, List<String> ciphers, String name) {
        for (String c: supportedCiphers) {
            if (name.equals(c)) {
                ciphers.add(c);
            }
        }
    }

    private final String[] cipherSuites;
    private final List<String> unmodifiableCipherSuites;

    JdkSslContext(SslBufferPool bufferPool, Iterable<String> ciphers) {
        super(bufferPool);
        cipherSuites = toCipherSuiteArray(ciphers);
        unmodifiableCipherSuites = Collections.unmodifiableList(Arrays.asList(cipherSuites));
    }

    public abstract SSLContext context();

    public final SSLSessionContext sessionContext() {
        if (isServer()) {
            return context().getServerSessionContext();
        } else {
            return context().getClientSessionContext();
        }
    }

    @Override
    public final List<String> cipherSuites() {
        return unmodifiableCipherSuites;
    }


    @Override
    public final long sessionCacheSize() {
        return sessionContext().getSessionCacheSize();
    }

    @Override
    public final long sessionTimeout() {
        return sessionContext().getSessionTimeout();
    }

    @Override
    public final SSLEngine newEngine() {
        SSLEngine engine = context().createSSLEngine();
        engine.setEnabledCipherSuites(cipherSuites);
        engine.setUseClientMode(isClient());
        return engine;
    }

    @Override
    public final SSLEngine newEngine(String host, int port) {
        SSLEngine engine = context().createSSLEngine(host, port);
        engine.setEnabledCipherSuites(cipherSuites);
        engine.setUseClientMode(isClient());
        return engine;
    }

    @Override
    public final SslHandler newHandler() {
        return new SslHandler(newEngine(), bufferPool());
    }

    @Override
    public final SslHandler newHandler(String host, int port) {
        return new SslHandler(newEngine(host, port), bufferPool());
    }

    private static String[] toCipherSuiteArray(Iterable<String> ciphers) {
        if (ciphers == null) {
            return DEFAULT_CIPHERS.toArray(new String[DEFAULT_CIPHERS.size()]);
        } else {
            List<String> newCiphers = new ArrayList<String>();
            for (String c: ciphers) {
                if (c == null) {
                    break;
                }
                newCiphers.add(c);
            }
            return newCiphers.toArray(new String[newCiphers.size()]);
        }
    }
}
