package io.softwarity.lib.ldap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Objects;
import java.util.Set;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LdapSearch {

    String GROUPS_FILTER = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=group))";

    /**
     * initContext
     * 
     * @param url
     * @return
     * @throws NamingException
     */
    public InitialLdapContext initContext(String url) throws NamingException {
        log.debug("Connection to LDAP server - URL: {}", url);
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url); // ldaps://ldap.hhome.fr:636
        env.put(Context.REFERRAL, "follow");
        InitialLdapContext context = new InitialLdapContext(env, null);
        return context;
    }

    /**
     * Add ZZ option, define that we want to use start TLS option, need certificate
     * 
     * @param context
     * @param cert
     * @return
     * @throws IOException
     * @throws NamingException
     */
    public StartTlsResponse addZZOption(InitialLdapContext context, String cert, boolean ignoreCertHostname) throws IOException, NamingException {
        StartTlsResponse tls = (StartTlsResponse) context.extendedOperation(new StartTlsRequest());
        try {
            // get SSL context linked with KeyStore
            SSLContext sslContext = getSSLContext(cert);
            // Install hostname verifie
            if (ignoreCertHostname) {
                tls.setHostnameVerifier(new IgnoreHostNameVerifier());
            }
            // Perform TLS negotiations
            tls.negotiate(sslContext.getSocketFactory());
        } catch (Throwable t) {
            t.printStackTrace();
        }
        return tls;
    }

    /**
     * Connect with simple credential
     * 
     * @param context
     * @param login
     * @param password
     * @throws NamingException
     */
    public void connect(InitialLdapContext context, String login, String password) throws NamingException {
        context.addToEnvironment(Context.SECURITY_AUTHENTICATION, "simple");
        context.addToEnvironment(Context.SECURITY_PRINCIPAL, login);
        context.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
    }

    public LdapResult search(DirContext context, String D, String b, String filter, String login) throws NamingException {
        LdapResult ldapResult = new LdapResult();
        // Specify the attributes to return
        SearchControls searchControls = getSearchControls(new String[] { "*", "memberOf" });
        // Perform the search
        NamingEnumeration<SearchResult> results = context.search(b, filter, new String[] { login }, searchControls);
        // Process the results
        boolean cont = true;
        while (cont && results.hasMore()) {
            SearchResult result = results.next();
            Attributes attrs = result.getAttributes();
            if (result.getNameInNamespace().matches(String.format("^\\w{2,3}=%s,.*", login))) {
                cont = false; // we found the user 
                for (NamingEnumeration<? extends Attribute> ae = attrs.getAll(); ae.hasMore();) {
                    Attribute attr = ae.next();
                    if (!ldapResult.containsKey(attr.getID())) {
                        ldapResult.put(attr.getID(), new ArrayList<>());
                    }
                    if (attr.getID().equalsIgnoreCase("memberOf")) {
                      Set<String> allGroups = new HashSet<>();
                      for (NamingEnumeration<?> e = attr.getAll(); e.hasMore();) {
                          String groupDn = (String) e.next();
                          allGroups.add(groupDn);
                          findNestedGroupsBasedOn(context, groupDn, allGroups);
                      }
                      ldapResult.get("memberOf").addAll(allGroups);
                    } else {
                      ldapResult.get(attr.getID()).add(attr.get().toString());
                    }
                }
            }
        }
        return ldapResult;
    }

    private void findNestedGroupsBasedOn(DirContext ctx, String groupDn, Set<String> allGroups) {
        SearchControls searchControls = getSearchControls(new String[] {"*", "memberOf" });
        try {
            NamingEnumeration<SearchResult> results = ctx.search(groupDn, GROUPS_FILTER, searchControls);
            while (results.hasMore()) {
                SearchResult result = results.next();
                if (result.getNameInNamespace().equals(groupDn)) {
                    Attributes attrs = result.getAttributes();
                    Attribute memberOfAttr = attrs.get("memberOf");
                    if (memberOfAttr != null) {
                        for (NamingEnumeration<?> e = memberOfAttr.getAll(); e.hasMore();) {
                            String nestedGroupDn = (String) e.next();
                            if (allGroups.add(nestedGroupDn)) {
                                findNestedGroupsBasedOn(ctx, nestedGroupDn, allGroups);
                            }
                        }
                    }
                }
            }
        } catch (NamingException e) {
            log.error("Error while finding nested groups: " + e.getMessage());
        }
    }

    public String createBindPrincipal(String login, String userDNPattern) {
        if (Objects.nonNull(userDNPattern) && !userDNPattern.isEmpty()) {
            return userDNPattern.replace("{0}", login);
        }
        return login;
    }

    private SSLContext getSSLContext(String cert) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        if (Objects.nonNull(cert)) {
            try (InputStream certIn = new ByteArrayInputStream(cert.getBytes())) {
                keyStore.setCertificateEntry("ldap",
                        CertificateFactory.getInstance("X.509").generateCertificate(certIn));
            }
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, null);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    private SearchControls getSearchControls(String[] attrIDs) {
      SearchControls searchControls = new SearchControls();
      searchControls.setReturningAttributes(attrIDs);
      searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
      return searchControls;
    }
}
