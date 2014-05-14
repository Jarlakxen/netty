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

import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.SSL;
import org.apache.tomcat.jni.SSLContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Creates a new {@link OpenSslEngine}.  Internally, this factory keeps the SSL_CTX object of OpenSSL.
 * This factory is intended for a shared use by multiple channels:
 * <pre>
 * public class MyChannelPipelineFactory extends {@link ChannelPipelineFactory} {
 *
 *     private final {@link OpenSslContext} sslEngineFactory = ...;
 *
 *     public {@link ChannelPipeline} getPipeline() {
 *         {@link ChannelPipeline} p = {@link Channels#pipeline() Channels.pipeline()};
 *         p.addLast("ssl", new {@link SslHandler}(sslEngineFactory.newEngine()));
 *         ...
 *         return p;
 *     }
 * }
 * </pre>
 *
 */
public final class OpenSslContext extends SslContext {

    private static final InternalLogger logger = InternalLoggerFactory.getInstance(OpenSslContext.class);
    private static final List<String> DEFAULT_CIPHERS;

    static {
        List<String> ciphers = new ArrayList<String>();
        // XXX: Make sure to sync this list with JdkSslEngineFactory.
        Collections.addAll(
                ciphers,
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-RSA-RC4-SHA",
                "ECDHE-RSA-AES128-SHA",
                "ECDHE-RSA-AES256-SHA",
                "AES128-GCM-SHA256",
                "RC4-SHA",
                "RC4-MD5",
                "AES128-SHA",
                "AES256-SHA",
                "DES-CBC3-SHA");
        DEFAULT_CIPHERS = Collections.unmodifiableList(ciphers);


        if (logger.isDebugEnabled()) {
            logger.debug("Default cipher suite (OpenSSL): " + ciphers);
        }
    }

    private final long aprPool;
    private final SslBufferPool bufPool;

    private final List<String> ciphers = new ArrayList<String>();
    private final List<String> unmodifiableCiphers = Collections.unmodifiableList(ciphers);
    private final long sessionCacheSize;
    private final long sessionTimeout;
    private final List<String> nextProtocols = new ArrayList<String>();
    private final List<String> unmodifiableNextProtocols = Collections.unmodifiableList(nextProtocols);

    /** The OpenSSL SSL_CTX object */
    private final long ctx;
    private final OpenSslSessionStats stats;

    public OpenSslContext(
            SslBufferPool bufPool,
            String certChainPath, String keyPath, String keyPassword,
            Iterable<String> ciphers, Iterable<String> nextProtocols,
            long sessionCacheSize, long sessionTimeout) throws SSLException {

        OpenSsl.ensureAvailability();

        if (certChainPath == null) {
            throw new NullPointerException("certChainPath");
        }
        if (!new File(certChainPath).isFile()) {
            throw new IllegalArgumentException("certChainPath is not a file: " + certChainPath);
        }
        if (keyPath == null) {
            throw new NullPointerException("keyPath");
        }
        if (!new File(keyPath).isFile()) {
            throw new IllegalArgumentException("keyPath is not a file: " + keyPath);
        }
        if (ciphers == null) {
            ciphers = DEFAULT_CIPHERS;
        }

        if (keyPassword == null) {
            keyPassword = "";
        }
        if (nextProtocols == null) {
            nextProtocols = Collections.emptyList();
        }

        for (String c: ciphers) {
            if (c == null) {
                break;
            }
            this.ciphers.add(c);
        }

        for (String p: nextProtocols) {
            if (p == null) {
                break;
            }
            this.nextProtocols.add(p);
        }

        // Allocate a new APR pool.
        aprPool = Pool.create(0);

        // Allocate a new direct buffer pool if necessary.
        boolean success = false;
        try {
            if (bufPool == null) {
                bufPool = new SslBufferPool(true);
            }
            success = true;
        } finally {
            if (!success) {
                Pool.destroy(aprPool);
            }
        }

        this.bufPool = bufPool;

        // Create a new SSL_CTX and configure it.
        success = false;
        try {
            synchronized (OpenSslContext.class) {
                try {
                    ctx = SSLContext.make(aprPool, SSL.SSL_PROTOCOL_ALL, SSL.SSL_MODE_SERVER);
                } catch (Exception e) {
                    throw new SSLException("failed to create an SSL_CTX", e);
                }

                SSLContext.setOptions(ctx, SSL.SSL_OP_ALL);
                SSLContext.setOptions(ctx, SSL.SSL_OP_NO_SSLv2);
                SSLContext.setOptions(ctx, SSL.SSL_OP_CIPHER_SERVER_PREFERENCE);
                SSLContext.setOptions(ctx, SSL.SSL_OP_SINGLE_ECDH_USE);
                SSLContext.setOptions(ctx, SSL.SSL_OP_SINGLE_DH_USE);
                SSLContext.setOptions(ctx, SSL.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

                /* List the ciphers that the client is permitted to negotiate. */
                try {
                    // Convert the cipher list into a colon-separated string.
                    StringBuilder cipherBuf = new StringBuilder();
                    for (String c: this.ciphers) {
                        cipherBuf.append(c);
                        cipherBuf.append(':');
                    }
                    cipherBuf.setLength(cipherBuf.length() - 1);

                    SSLContext.setCipherSuite(ctx, cipherBuf.toString());
                } catch (SSLException e) {
                    throw e;
                } catch (Exception e) {
                    throw new SSLException("failed to set cipher suite: " + this.ciphers, e);
                }

                /* Set certificate verification policy. */
                SSLContext.setVerify(ctx, SSL.SSL_CVERIFY_NONE, 10);

                /* Load the certificate file and private key. */
                try {
                    if (!SSLContext.setCertificate(
                            ctx, certChainPath, keyPath, keyPassword, SSL.SSL_AIDX_RSA)) {
                        throw new SSLException("failed to set certificate: " +
                                certChainPath + " and " + keyPath + " (" + SSL.getLastError() + ')');
                    }
                } catch (SSLException e) {
                    throw e;
                } catch (Exception e) {
                    throw new SSLException("failed to set certificate: " + certChainPath + " and " + keyPath, e);
                }

                /* Load the certificate chain. We must skip the first cert since it was loaded above. */
                if (!SSLContext.setCertificateChainFile(ctx, certChainPath, true)) {
                    String error = SSL.getLastError();
                    if (!error.startsWith(OpenSsl.IGNORABLE_ERROR_PREFIX)) {
                        throw new SSLException(
                                "failed to set certificate chain: " + certChainPath + " (" + SSL.getLastError() + ')');
                    }
                }

                /* Set next protocols for next protocol negotiation extension, if specified */
                if (!this.nextProtocols.isEmpty()) {
                    // Convert the protocol list into a comma-separated string.
                    StringBuilder nextProtocolBuf = new StringBuilder();
                    for (String p: this.nextProtocols) {
                        nextProtocolBuf.append(p);
                        nextProtocolBuf.append(',');
                    }
                    nextProtocolBuf.setLength(nextProtocolBuf.length() - 1);

                    SSLContext.setNextProtos(ctx, nextProtocolBuf.toString());
                }

                /* Set session cache size, if specified */
                if (sessionCacheSize > 0) {
                    this.sessionCacheSize = sessionCacheSize;
                    SSLContext.setSessionCacheSize(ctx, sessionCacheSize);
                } else {
                    // Get the default session cache size using SSLContext.setSessionCacheSize()
                    this.sessionCacheSize = sessionCacheSize = SSLContext.setSessionCacheSize(ctx, 20480);
                    // Revert the session cache size to the default value.
                    SSLContext.setSessionCacheSize(ctx, sessionCacheSize);
                }

                /* Set session timeout, if specified */
                if (sessionTimeout > 0) {
                    this.sessionTimeout = sessionTimeout;
                    SSLContext.setSessionCacheTimeout(ctx, sessionTimeout);
                } else {
                    // Get the default session timeout using SSLContext.setSessionCacheTimeout()
                    this.sessionTimeout = sessionTimeout = SSLContext.setSessionCacheTimeout(ctx, 300);
                    // Revert the session timeout to the default value.
                    SSLContext.setSessionCacheTimeout(ctx, sessionTimeout);
                }
            }
            success = true;
        } finally {
            if (!success) {
                destroyPools();
            }
        }

        stats = new OpenSslSessionStats(ctx);
    }

    @Override
    public boolean isClient() {
        return false;
    }

    @Override
    public List<String> cipherSuites() {
        return unmodifiableCiphers;
    }

    @Override
    public long sessionCacheSize() {
        return sessionCacheSize;
    }

    @Override
    public long sessionTimeout() {
        return sessionTimeout;
    }

    @Override
    public ApplicationProtocolSelector nextProtocolSelector() {
        return null;
    }

    @Override
    public List<String> nextProtocols() {
        return unmodifiableNextProtocols;
    }

    /**
     * Returns the {@code SSL_CTX} object of this factory.
     */
    public long context() {
        return ctx;
    }

    public OpenSslSessionStats stats() {
        return stats;
    }

    @Override
    public SslBufferPool bufPool() {
        return bufPool;
    }

    /**
     * Returns a new server-side {@link SSLEngine} with the current configuration.
     */
    @Override
    public SSLEngine newEngine() {
        return new OpenSslEngine(ctx, bufPool);
    }

    @Override
    public SslHandler newHandler() {
        return new SslHandler(newEngine(), bufPool);
    }

    public void setTicketKeys(byte[] keys) {
        SSLContext.setSessionTicketKeys(ctx, keys);
    }

    @Override
    @SuppressWarnings("FinalizeDeclaration")
    protected void finalize() throws Throwable {
        super.finalize();
        synchronized (OpenSslContext.class) {
            if (ctx != 0) {
                SSLContext.free(ctx);
            }
        }

        destroyPools();
    }

    private void destroyPools() {
        if (aprPool != 0) {
            Pool.destroy(aprPool);
        }
    }
}
