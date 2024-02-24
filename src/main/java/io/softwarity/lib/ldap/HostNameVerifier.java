package io.softwarity.lib.ldap;

import java.security.cert.Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import lombok.extern.slf4j.Slf4j;

/**
 * This is used only if default macher doesnt match.
 * Mean dont find certificate for the host name specify with the same host
 */
@Slf4j
public class HostNameVerifier implements HostnameVerifier {

    public boolean verify(String hostname, SSLSession session) {
        log.debug("Default matching {} and ceritficate failed. Custom HostNameVerifier, valid it", hostname);
        try {
            Certificate[] cert = session.getPeerCertificates();
            for (int i = 0; i < cert.length; i++) {
                log.debug(cert[i].toString());
            }
        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
            return true;
        }
        return true; 	    // Never do this
    }
}
