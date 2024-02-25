package io.softwarity.lib.ldap;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * This is used only if default macher doesnt match.
 * Mean dont find certificate for the host name specify with the same host
 */
public class IgnoreHostNameVerifier implements HostnameVerifier {

    /**
     * Verifies the hostname of the server during SSL/TLS handshake.
     *
     * @param hostname the hostname to be verified
     * @param session  the SSL session
     * @return true if the hostname is verified, false otherwise
     */
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
}
