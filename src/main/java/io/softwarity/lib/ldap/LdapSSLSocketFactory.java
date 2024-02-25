package io.softwarity.lib.ldap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Map.Entry;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class LdapSSLSocketFactory extends SSLSocketFactory {
    private SSLSocketFactory socketFactory;

    private static Map<String, String> certs = new HashMap<>();

    public static void addCert(String alias, String cert) {
        LdapSSLSocketFactory.certs.put(alias, cert);
    }

    public LdapSSLSocketFactory() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);  // load an empty keystore
            LdapSSLSocketFactory.certs.entrySet().forEach((Entry<String, String> entry) -> {
                try {
                    if (Objects.nonNull(entry.getValue())) {
                        try (InputStream certIn = new ByteArrayInputStream(entry.getValue().getBytes())) {
                            keyStore.setCertificateEntry(entry.getKey(), CertificateFactory.getInstance("X.509").generateCertificate(certIn));
                        }
                    }
                } catch (Exception ex) {
                    ex.printStackTrace(System.err);
                }
            });

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, null);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
            socketFactory = sslContext.getSocketFactory();
        } catch (Exception ex) {
            ex.printStackTrace(System.err);
        }
    }

    public static SocketFactory getDefault() {
        return new LdapSSLSocketFactory();
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return socketFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return socketFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean bln) throws IOException {
        return socketFactory.createSocket(socket, host, port, bln);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return socketFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress ia, int i1) throws IOException, UnknownHostException {
        return socketFactory.createSocket(host, port, ia, i1);
    }

    @Override
    public Socket createSocket(InetAddress ia, int i) throws IOException {
        return socketFactory.createSocket(ia, i);
    }

    @Override
    public Socket createSocket(InetAddress ia, int i, InetAddress ia1, int i1) throws IOException {
        return socketFactory.createSocket(ia, i, ia1, i1);
    }

    @Override
    public Socket createSocket() throws IOException {
        return socketFactory.createSocket();
    }
}
