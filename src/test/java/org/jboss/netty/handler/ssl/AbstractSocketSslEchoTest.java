/*
 * Copyright 2012 The Netty Project
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

import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.execution.ExecutionHandler;
import org.jboss.netty.handler.execution.OrderedMemoryAwareThreadPoolExecutor;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.TestUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

// TODO: Merge all subclasses and test parameters using Parameterized.
@RunWith(Parameterized.class)
public abstract class AbstractSocketSslEchoTest {
    static final InternalLogger logger = InternalLoggerFactory.getInstance(AbstractSocketSslEchoTest.class);

    private static final Random random = new Random();
    static final byte[] data = new byte[1048576];

    private static final String CERT_PATH;
    private static final String KEY_PATH;

    static {
        random.nextBytes(data);

        // Copy the self-signed certificate and its private key into a temporary directory.
        final String certPath;
        final String keyPath;
        try {
            certPath = File.createTempFile("netty_ssl_test_", ".crt").getAbsolutePath();
            new File(certPath).deleteOnExit();
            keyPath = File.createTempFile("netty_ssl_test_", ".pem").getAbsolutePath();
            new File(keyPath).deleteOnExit();

            ClassLoader cl = AbstractSocketSslEchoTest.class.getClassLoader();
            FileOutputStream certOut = new FileOutputStream(certPath);
            InputStream certIn = cl.getResourceAsStream("openssl.crt");
            for (;;) {
                int b = certIn.read();
                if (b < 0) {
                    break;
                }
                certOut.write(b);
            }
            certOut.close();

            FileOutputStream keyOut = new FileOutputStream(keyPath);
            InputStream keyIn = cl.getResourceAsStream("openssl.pem");
            for (;;) {
                int b = keyIn.read();
                if (b < 0) {
                    break;
                }
                keyOut.write(b);
            }
            keyOut.close();
        } catch (Exception e) {
            throw new Error("failed to copy the self-signed certificate", e);
        }

        CERT_PATH = certPath;
        KEY_PATH = keyPath;
    }

    @Parameters(name = "{index}: serverCtx = {0}, clientCtx = {1}")
    public static Collection<SslContext[]> sslContexts() throws Exception {
        // Populate the permutations.
        List<SslContext[]> params = new ArrayList<SslContext[]>();

        List<SslContext> serverContexts = new ArrayList<SslContext>();
        serverContexts.add(new JdkSslContext(null, CERT_PATH, KEY_PATH, null, null, null, 0, 0));

        List<SslContext> clientContexts = new ArrayList<SslContext>();
        clientContexts.add(new JdkSslContext(null, CERT_PATH, null, null, null, 0, 0));

        boolean hasOpenSsl = OpenSsl.isAvailable();
        if (hasOpenSsl) {
            serverContexts.add(new OpenSslContext(null, CERT_PATH, KEY_PATH, null, null, null, 0, 0));

            // TODO: Client mode is not supported yet.
            // clientContexts.add(new OpenSslContext(null, CERT_PATH, null, null, null, 0, 0));
        } else {
            logger.warn("OpenSSL is unavailable and thus will not be tested.", OpenSsl.unavailabilityCause());
        }

        for (SslContext sctx: serverContexts) {
            for (SslContext cctx: clientContexts) {
                params.add(new SslContext[] { sctx, cctx });
            }
        }

        return params;
    }

    private final SslContext serverCtx;
    private final SslContext clientCtx;

    protected AbstractSocketSslEchoTest(SslContext serverCtx, SslContext clientCtx) {
        this.serverCtx = serverCtx;
        this.clientCtx = clientCtx;
    }

    protected abstract ChannelFactory newServerSocketChannelFactory(Executor executor);
    protected abstract ChannelFactory newClientSocketChannelFactory(Executor executor);

    protected boolean isExecutorRequired() {
        return false;
    }

    @Test
    public void testSslEcho1() throws Throwable {
        testSslEcho(false, false);
    }

    @Test
    public void testSslEcho2() throws Throwable {
        testSslEcho(false, true);
    }

    @Test
    public void testSslEcho3() throws Throwable {
        testSslEcho(true, false);
    }

    @Test
    public void testSslEcho4() throws Throwable {
        testSslEcho(true, true);
    }

    @SuppressWarnings("deprecation")
    private void testSslEcho(
            boolean serverUsesDelegatedTaskExecutor, boolean clientUsesDelegatedTaskExecutor) throws Throwable {
        ExecutorService delegatedTaskExecutor = Executors.newCachedThreadPool();
        ServerBootstrap sb = new ServerBootstrap(newServerSocketChannelFactory(Executors.newCachedThreadPool()));
        ClientBootstrap cb = new ClientBootstrap(newClientSocketChannelFactory(Executors.newCachedThreadPool()));

        EchoHandler sh = new EchoHandler(true);
        EchoHandler ch = new EchoHandler(false);

        // Workaround for blocking I/O transport write-write dead lock.
        sb.setOption("receiveBufferSize", 1048576);
        sb.setOption("receiveBufferSize", 1048576);

        // Configure the server pipeline.
        if (serverUsesDelegatedTaskExecutor) {
            sb.getPipeline().addFirst(
                    "ssl", new SslHandler(serverCtx.newEngine(), serverCtx.bufPool(), delegatedTaskExecutor));
        } else {
            sb.getPipeline().addFirst("ssl", serverCtx.newHandler());
        }
        sb.getPipeline().addLast("handler", sh);

        // Configure the client pipeline.
        if (clientUsesDelegatedTaskExecutor) {
            cb.getPipeline().addFirst(
                    "ssl", new SslHandler(clientCtx.newEngine(), clientCtx.bufPool(), delegatedTaskExecutor));
        } else {
            cb.getPipeline().addFirst("ssl", clientCtx.newHandler());
        }
        cb.getPipeline().addLast("handler", ch);

        ExecutorService eventExecutor = null;
        if (isExecutorRequired()) {
            eventExecutor = new OrderedMemoryAwareThreadPoolExecutor(16, 0, 0);
            sb.getPipeline().addFirst("executor", new ExecutionHandler(eventExecutor));
            cb.getPipeline().addFirst("executor", new ExecutionHandler(eventExecutor));
        }

        Channel sc = sb.bind(new InetSocketAddress(0));
        int port = ((InetSocketAddress) sc.getLocalAddress()).getPort();

        ChannelFuture ccf = cb.connect(new InetSocketAddress(TestUtil.getLocalHost(), port));
        ccf.awaitUninterruptibly();
        if (!ccf.isSuccess()) {
            logger.error("Connection attempt failed", ccf.getCause());
            sc.close().awaitUninterruptibly();
        }
        assertTrue(ccf.isSuccess());

        Channel cc = ccf.getChannel();
        ChannelFuture hf = cc.getPipeline().get(SslHandler.class).handshake();
        hf.awaitUninterruptibly();
        if (!hf.isSuccess()) {
            logger.error("Handshake failed", hf.getCause());
            sh.channel.close().awaitUninterruptibly();
            ch.channel.close().awaitUninterruptibly();
            sc.close().awaitUninterruptibly();
        }

        assertTrue(hf.isSuccess());

        for (int i = 0; i < data.length;) {
            int length = Math.min(random.nextInt(1024 * 64), data.length - i);
            cc.write(ChannelBuffers.wrappedBuffer(data, i, length));
            i += length;
        }

        while (ch.counter < data.length) {
            if (sh.exception.get() != null) {
                break;
            }
            if (ch.exception.get() != null) {
                break;
            }

            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                // Ignore.
            }
        }

        while (sh.counter < data.length) {
            if (sh.exception.get() != null) {
                break;
            }
            if (ch.exception.get() != null) {
                break;
            }

            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                // Ignore.
            }
        }

        sh.channel.close().awaitUninterruptibly();
        ch.channel.close().awaitUninterruptibly();
        sc.close().awaitUninterruptibly();
        cb.shutdown();
        sb.shutdown();
        cb.releaseExternalResources();
        sb.releaseExternalResources();
        delegatedTaskExecutor.shutdown();

        if (eventExecutor != null) {
            eventExecutor.shutdown();
        }
        if (sh.exception.get() != null && !(sh.exception.get() instanceof IOException)) {
            throw sh.exception.get();
        }
        if (ch.exception.get() != null && !(ch.exception.get() instanceof IOException)) {
            throw ch.exception.get();
        }
        if (sh.exception.get() != null) {
            throw sh.exception.get();
        }
        if (ch.exception.get() != null) {
            throw ch.exception.get();
        }
    }

    private static class EchoHandler extends SimpleChannelUpstreamHandler {
        volatile Channel channel;
        final AtomicReference<Throwable> exception = new AtomicReference<Throwable>();
        volatile int counter;
        private final boolean server;

        EchoHandler(boolean server) {
            this.server = server;
        }

        @Override
        public void channelOpen(ChannelHandlerContext ctx, ChannelStateEvent e)
                throws Exception {
            channel = e.getChannel();
        }

        @Override
        public void messageReceived(ChannelHandlerContext ctx, MessageEvent e)
                throws Exception {
            ChannelBuffer m = (ChannelBuffer) e.getMessage();
            byte[] actual = new byte[m.readableBytes()];
            m.getBytes(0, actual);

            int lastIdx = counter;
            for (int i = 0; i < actual.length; i ++) {
                assertEquals(data[i + lastIdx], actual[i]);
            }

            if (channel.getParent() != null) {
                channel.write(m);
            }

            counter += actual.length;
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e)
                throws Exception {
            logger.warn(
                    "Unexpected exception from the " +
                    (server? "server" : "client") + " side", e.getCause());

            exception.compareAndSet(null, e.getCause());
            e.getChannel().close();
        }
    }
}
