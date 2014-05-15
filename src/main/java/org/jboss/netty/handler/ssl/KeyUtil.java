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
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.base64.Base64;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.CharsetUtil;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads a PEM file and converts it into a {@link KeyStore}.
 */
public final class KeyUtil {

    private static final InternalLogger logger = InternalLoggerFactory.getInstance(KeyUtil.class);

    private static final Pattern CERT_PATTERN = Pattern.compile(
            "-+BEGIN\\s+.*CERTIFICATE[^-]*-+(?:\\s|\\r|\\n)+" + // Header
                    "([a-z0-9+/=\\r\\n]+)" +                    // Base64 text
                    "-+END\\s+.*CERTIFICATE[^-]*-+",            // Footer
            Pattern.CASE_INSENSITIVE);
    private static final Pattern KEY_PATTERN = Pattern.compile(
            "-+BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+" + // Header
                    "([a-z0-9+/=\\r\\n]+)" +                       // Base64 text
                    "-+END\\s+.*PRIVATE\\s+KEY[^-]*-+",            // Footer
            Pattern.CASE_INSENSITIVE);

    /** Current time minus 1 year, just in case software clock goes back due to time synchronization */
    static final Date NOT_BEFORE = new Date(System.currentTimeMillis() - 86400000L * 365);
    /** The maximum possible value in X.509 specification: 9999-12-31 23:59:59 */
    static final Date NOT_AFTER = new Date(253402300799000L);

    public static ChannelBuffer[] readCertificates(String filePath) throws IOException {
        return readCertificates(new FileInputStream(filePath));
    }

    public static ChannelBuffer[] readCertificates(InputStream in) throws IOException {
        String content = readContent(in);

        List<ChannelBuffer> certs = new ArrayList<ChannelBuffer>();
        Matcher m = CERT_PATTERN.matcher(content);
        int start = 0;
        for (;;) {
            if (!m.find(start)) {
                break;
            }

            certs.add(Base64.decode(ChannelBuffers.copiedBuffer(m.group(1), CharsetUtil.US_ASCII)));
            start = m.end();
        }

        if (certs.isEmpty()) {
            throw new IllegalArgumentException("found no certificates");
        }

        return certs.toArray(new ChannelBuffer[certs.size()]);
    }

    public static ChannelBuffer readPrivateKey(String filePath) throws IOException {
        return readPrivateKey(new FileInputStream(filePath));
    }

    public static ChannelBuffer readPrivateKey(InputStream in) throws IOException {
        String content = readContent(in);

        Matcher m = KEY_PATTERN.matcher(content);
        if (!m.find()) {
            throw new IllegalArgumentException("found no private key");
        }

        return Base64.decode(ChannelBuffers.copiedBuffer(m.group(1), CharsetUtil.US_ASCII));
    }

    public static String[] newSelfSignedCertificate() {
        return newSelfSignedCertificate("example.com");
    }

    /**
     * Generates a temporary self-signed certificate for testing purposes.
     * A X.509 certificate file and a RSA private key file are generated in a system's temporary directory
     * using {@link File#createTempFile(String, String)}, and they are deleted when the JVM exits
     * using {@link File#deleteOnExit()}.
     * <p>
     * At first, this method tries to use OpenJDK's X.509 implementation ({@code sun.security.x509}).
     * If it fails, it secondly tries to use <a href="http://www.bouncycastle.org/">Bouncy Castle</a>.
     * </p>
     *
     * @return a {@link String} array whose 0th element is the path to the X.509 certificate file and
     *         whose 1st element is the path to the RSA private key file
     *
     * @throws UnsupportedOperationException if both OpenJDK proprietary API and Bouncy Castle are unavailable
     */
    public static String[] newSelfSignedCertificate(String fqdn) {
        try {
            // Bypass entrophy collection by using insecure random generator.
            // We just want to generate it without any delay because it's for testing purposes only.
            SecureRandom random = ThreadLocalInsecureRandom.current();

            // Generate a 1024-bit RSA key pair.
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024, random);
            KeyPair keypair = keyGen.generateKeyPair();

            // Try Bouncy Castle.
            return BouncyCastleSelfSignedCertGenerator.generate(fqdn, keypair, random);
            // Try the OpenJDK's proprietary implementation.
            //return OpenJdkSelfSignedCertGenerator.generate(fqdn);
        } catch (Throwable t) {
            throw new UnsupportedOperationException("no provider succeeded to generate a self-signed certificate.", t);
        }
    }

    static String[] newSelfSignedCertificate(
            String fqdn, PrivateKey key, X509Certificate cert) throws IOException, CertificateEncodingException {

        // Encode the private key into a file.
        String keyText = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.encode(ChannelBuffers.wrappedBuffer(key.getEncoded()), true).toString(CharsetUtil.US_ASCII) +
                "\n-----END PRIVATE KEY-----\n";

        File keyFile = File.createTempFile("keyutil_" + fqdn + '_', ".key");
        keyFile.deleteOnExit();

        OutputStream keyOut = new FileOutputStream(keyFile);
        try {
            keyOut.write(keyText.getBytes(CharsetUtil.US_ASCII));
            keyOut.close();
            keyOut = null;
        } finally {
            if (keyOut != null) {
                safeClose(keyFile, keyOut);
                safeDelete(keyFile);
            }
        }

        // Encode the certificate into a CRT file.
        String certText = "-----BEGIN CERTIFICATE-----\n" +
                Base64.encode(ChannelBuffers.wrappedBuffer(cert.getEncoded()), true).toString(CharsetUtil.US_ASCII) +
                "\n-----END CERTIFICATE-----\n";

        File certFile = File.createTempFile("keyutil_" + fqdn + '_', ".crt");
        certFile.deleteOnExit();

        OutputStream certOut = new FileOutputStream(certFile);
        try {
            certOut.write(certText.getBytes(CharsetUtil.US_ASCII));
            certOut.close();
            certOut = null;
        } finally {
            if (certOut != null) {
                safeClose(certFile, certOut);
                safeDelete(certFile);
                safeDelete(keyFile);
            }
        }

        return new String[] { certFile.getPath(), keyFile.getPath() };
    }

    private static String readContent(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            byte[] buf = new byte[8192];
            for (;;) {
                int ret = in.read(buf);
                if (ret < 0) {
                    break;
                }
                out.write(buf, 0, ret);
            }
        } finally {
            try {
                in.close();
            } catch (IOException e) {
                logger.warn("Failed to close a stream.", e);
            }
        }

        return out.toString(CharsetUtil.US_ASCII.name());
    }

    private static void safeDelete(File certFile) {
        if (!certFile.delete()) {
            logger.warn("Failed to delete a file: " + certFile);
        }
    }

    private static void safeClose(File keyFile, OutputStream keyOut) {
        try {
            keyOut.close();
        } catch (IOException e) {
            logger.warn("Failed to close a file: " + keyFile, e);
        }
    }

    private KeyUtil() { }
}
