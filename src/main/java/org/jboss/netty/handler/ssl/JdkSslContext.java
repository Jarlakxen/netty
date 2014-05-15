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

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferInputStream;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class JdkSslContext extends SslContext {

    private static final InternalLogger logger = InternalLoggerFactory.getInstance(JdkSslContext.class);

    private static final List<String> DEFAULT_CIPHERS;
    private static final String PROTOCOL = "TLS";

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

    private static final byte[] EMPTY_KEYSTORE = {
            (byte) 0xfe, (byte) 0xed, (byte) 0xfe, (byte) 0xed, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            (byte) 0xe2, 0x68, 0x6e, 0x45, (byte) 0xfb, 0x43, (byte) 0xdf, (byte) 0xa4, (byte) 0xd9, (byte) 0x92,
            (byte) 0xdd, 0x41, (byte) 0xce, (byte) 0xb6, (byte) 0xb2, 0x1c, 0x63, 0x30, (byte) 0xd7, (byte) 0x92
    };
    private static final char[] EMPTY_KEYSTORE_PASSWORD = "changeit".toCharArray();

    private final boolean client;
    private final SslBufferPool bufPool;
    private final SSLContext ctx;
    private final SSLSessionContext sessCtx;
    private final String[] ciphers;
    private final List<String> unmodifiableCiphers;

    /**
     * Creates a new factory that creates a new server-side {@link SSLEngine}.
     */
    public JdkSslContext(
            SslBufferPool bufPool,
            String certChainPath, String keyPath, String keyPassword,
            Iterable<String> ciphers, Iterable<String> nextProtocols,
            long sessionCacheSize, long sessionTimeout) throws SSLException {

        if (certChainPath == null) {
            throw new NullPointerException("certChainPath");
        }
        if (keyPath == null) {
            throw new NullPointerException("keyPath");
        }

        if (keyPassword == null) {
            keyPassword = "";
        }

        if (nextProtocols != null && nextProtocols.iterator().hasNext()) {
            throw new SSLException("NPN/ALPN unsupported: " + nextProtocols);
        }

        this.ciphers = toCipherSuiteArray(ciphers);
        unmodifiableCiphers = Collections.unmodifiableList(Arrays.asList(this.ciphers));
        this.bufPool = bufPool == null? new SslBufferPool(false) : bufPool;

        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        if (algorithm == null) {
            algorithm = "SunX509";
        }

        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new ByteArrayInputStream(EMPTY_KEYSTORE), EMPTY_KEYSTORE_PASSWORD);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            KeyFactory rsaKF = KeyFactory.getInstance("RSA");
            KeyFactory dsaKF = KeyFactory.getInstance("DSA");

            ChannelBuffer encodedKeyBuf = PemReader.readPrivateKey(keyPath);
            byte[] encodedKey = new byte[encodedKeyBuf.readableBytes()];
            encodedKeyBuf.readBytes(encodedKey);
            PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);

            PrivateKey key;
            try {
                key = rsaKF.generatePrivate(encodedKeySpec);
            } catch (InvalidKeySpecException ignore) {
                key = dsaKF.generatePrivate(encodedKeySpec);
            }

            List<Certificate> certChain = new ArrayList<Certificate>();
            for (ChannelBuffer buf: PemReader.readCertificates(certChainPath)) {
                certChain.add(cf.generateCertificate(new ChannelBufferInputStream(buf)));
            }

            ks.setKeyEntry("key", key, keyPassword.toCharArray(), certChain.toArray(new Certificate[certChain.size()]));

            // Set up key manager factory to use our key store
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(ks, keyPassword.toCharArray());

            // Initialize the SSLContext to work with our key managers.
            ctx = SSLContext.getInstance(PROTOCOL);
            ctx.init(kmf.getKeyManagers(), null, null);

            sessCtx = ctx.getServerSessionContext();
            if (sessionCacheSize > 0) {
                sessCtx.setSessionCacheSize((int) Math.min(sessionCacheSize, Integer.MAX_VALUE));
            }
            if (sessionTimeout > 0) {
                sessCtx.setSessionTimeout((int) Math.min(sessionTimeout, Integer.MAX_VALUE));
            }
        } catch (Exception e) {
            throw new SSLException("failed to initialize the server-side SSL context", e);
        }

        client = false;
    }

    /**
     * Creates a new factory that creates a new client-side {@link SSLEngine}.
     */
    public JdkSslContext(
            SslBufferPool bufPool, String certChainPath, TrustManagerFactory trustManagerFactory,
            Iterable<String> ciphers, ApplicationProtocolSelector nextProtocolSelector,
            long sessionCacheSize, long sessionTimeout) throws SSLException {

        if (nextProtocolSelector != null) {
            throw new SSLException("NPN/ALPN unsupported: " + nextProtocolSelector);
        }

        this.ciphers = toCipherSuiteArray(ciphers);
        unmodifiableCiphers = Collections.unmodifiableList(Arrays.asList(this.ciphers));
        this.bufPool = bufPool == null? new SslBufferPool(false) : bufPool;

        try {
            if (certChainPath == null) {
                ctx = SSLContext.getInstance(PROTOCOL);
                if (trustManagerFactory == null) {
                    ctx.init(null, null, null);
                } else {
                    trustManagerFactory.init((KeyStore) null);
                    ctx.init(null, trustManagerFactory.getTrustManagers(), null);
                }
            } else {
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(new ByteArrayInputStream(EMPTY_KEYSTORE), EMPTY_KEYSTORE_PASSWORD);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");

                for (ChannelBuffer buf: PemReader.readCertificates(certChainPath)) {
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ChannelBufferInputStream(buf));
                    X500Principal principal = cert.getSubjectX500Principal();
                    ks.setCertificateEntry(principal.getName("RFC2253"), cert);
                }

                // Set up trust manager factory to use our key store.
                if (trustManagerFactory == null) {
                    trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                }
                trustManagerFactory.init(ks);

                // Initialize the SSLContext to work with the trust managers.
                ctx = SSLContext.getInstance(PROTOCOL);
                ctx.init(null, trustManagerFactory.getTrustManagers(), null);
            }

            sessCtx = ctx.getServerSessionContext();
            if (sessionCacheSize > 0) {
                sessCtx.setSessionCacheSize((int) Math.min(sessionCacheSize, Integer.MAX_VALUE));
            }
            if (sessionTimeout > 0) {
                sessCtx.setSessionTimeout((int) Math.min(sessionTimeout, Integer.MAX_VALUE));
            }
        } catch (Exception e) {
            throw new SSLException("failed to initialize the server-side SSL context", e);
        }

        client = true;
    }

    @Override
    public boolean isClient() {
        return client;
    }

    @Override
    public List<String> cipherSuites() {
        return unmodifiableCiphers;
    }

    @Override
    public long sessionCacheSize() {
        return sessCtx.getSessionCacheSize();
    }

    @Override
    public long sessionTimeout() {
        return sessCtx.getSessionTimeout();
    }

    @Override
    public ApplicationProtocolSelector nextProtocolSelector() {
        return null;
    }

    @Override
    public List<String> nextProtocols() {
        return Collections.emptyList();
    }

    /**
     * Returns the {@link SSLContext} object of this factory.
     */
    public SSLContext context() {
        return ctx;
    }

    @Override
    public SslBufferPool bufferPool() {
        return bufPool;
    }

    @Override
    public SSLEngine newEngine() {
        SSLEngine engine = ctx.createSSLEngine();
        engine.setEnabledCipherSuites(ciphers);
        engine.setUseClientMode(client);
        return engine;
    }

    @Override
    public SslHandler newHandler() {
        return new SslHandler(newEngine(), bufPool);
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
