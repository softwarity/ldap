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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LdapSearch {

    /**
     * initContext
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
        return new InitialLdapContext(env, null);
    }

    /**
     * Add ZZ option, define that we want to use start TLS option, need certificate
     * @param context
     * @param cert
     * @return
     * @throws IOException
     * @throws NamingException
     */
    public StartTlsResponse addZZOption(InitialLdapContext context, String cert) throws IOException, NamingException {
        StartTlsResponse tls = (StartTlsResponse) context.extendedOperation(new StartTlsRequest());
        try {
            // get SSL context linked with KeyStore
            SSLContext sslContext = getSSLContext(cert);
            // Install hostname verifier
            tls.setHostnameVerifier(new HostNameVerifier());
            // Perform TLS negotiations
            tls.negotiate(sslContext.getSocketFactory());
        } catch(Throwable t) {
            t.printStackTrace();
        }
        return tls;
    }

    /**
     * Connect with simple credential
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

    public SearchResult searchForBaseDn(DirContext context, String baseDn, String filter, String[] filterArgs) throws NamingException {
        log.debug("                          - Get attributes for : {}", baseDn);
        SearchControls searchControls = getSearchControls(null);
        NamingEnumeration<SearchResult> resultsEnum = null;
        try {
            resultsEnum = context.search(baseDn, filter, filterArgs, searchControls);
            if (resultsEnum.hasMore()) {
                SearchResult searchResult = resultsEnum.next();
                findFirstLevelGroups(context, searchResult.getAttributes());
                return searchResult;
            }
        } finally {
            closeNamingEnumeration(resultsEnum);
        }
        throw new IllegalArgumentException("Search had no result");
    }

    public <T> Collection<T> getGroupNames(DirContext userData, Function<String, T> builder) {
        try {
            Attributes attrs = userData.getAttributes("");
            NamingEnumeration<? extends Attribute> attrEnum = attrs.getAll();
            List<String> groups = new ArrayList<>();
            while(attrEnum.hasMore()) {
                Attribute attr = attrEnum.next();
                if (attr.getID().equals("memberOf")) {
                    NamingEnumeration<?> memberOfEnum = attr.getAll();
                    while(memberOfEnum.hasMore()) {
                        String group = memberOfEnum.next().toString();
                        groups.add(group);
                    }
                }
            }
            if (groups.isEmpty()) {
                log.debug("No values for 'memberOf' attribute.");
            }
            log.debug("'memberOf' attribute values: {}", Arrays.asList(groups));
            return groups.stream().map((String group) -> {
                try {
                    List<Rdn> rnds = new LdapName(group).getRdns();
                    if (!rnds.isEmpty()) {
                        Rdn rnd = rnds.get(rnds.size() - 1);
                        Object val = rnd.getValue();
                        if (String.class.isInstance(val) && !((String) val).isEmpty()) {
                            return builder.apply((String) val);
                        }
                    }
                } catch (Exception e) {}
                return null;
            }).filter((T sga) -> Objects.nonNull(sga)).collect(Collectors.toList());
        } catch(NamingException ne) {
            ne.printStackTrace();
            return  Collections.emptyList();
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
                keyStore.setCertificateEntry("ldap", CertificateFactory.getInstance("X.509").generateCertificate(certIn));
            }
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, null);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    private void findFirstLevelGroups(DirContext context, Attributes attributes) throws NamingException {
        NamingEnumeration<? extends Attribute> all = null;
        try {
            all = attributes.getAll();
            log.debug("                          - Look for attribute memberOf...");
            while (all.hasMore()) {
                Attribute next = all.next();
                String attrName = next.getID();
                if (attrName.equals("memberOf")) {
                    Collection<String> groups = getGroupDns(next);
                    log.debug("                          - First level groups {}", groups);
                    groups.stream().forEach((String group) -> findNestedGroups(context, group, next));
                }
            }
        } finally {
            closeNamingEnumeration(all);
        }
    }


    private void findNestedGroups(DirContext context, String group, final Attribute memberOfAttr) {
        log.debug("                          - Look for nested group of {}...", group);
        SearchControls searchControls = getSearchControls(new String[]{"memberOf"});
        NamingEnumeration<SearchResult> resultsEnum = null;
        try {
            resultsEnum = context.search(group, "cn=*", searchControls);
            if (resultsEnum.hasMore()) {
                SearchResult searchResult = resultsEnum.next();
                Collection<String> groups = getGroupDns(searchResult.getAttributes().get("memberOf"));
                if (!groups.isEmpty()) {
                    log.debug("                          - Next level groups {}", groups);
                    groups.stream().filter((String grp) -> !memberOfAttr.contains(grp)).peek(memberOfAttr::add).forEach((String grp) -> findNestedGroups(context, grp, memberOfAttr));
                }
            }
        } catch (NamingException namingException) {
            throw new IllegalArgumentException(namingException);
        } finally {
            closeNamingEnumeration(resultsEnum);
        }
    }

    private Collection<String> getGroupDns(Attribute memberOfs) throws NamingException {
        Collection<String> groups = new ArrayList<>();
        if (Objects.nonNull(memberOfs) && memberOfs.size() > 0) {
            NamingEnumeration<?> all = null;
            try {
                all = memberOfs.getAll();
                while (all.hasMoreElements()) {
                    groups.add(all.nextElement().toString());
                }
            } finally {
                closeNamingEnumeration(all);
            }
        }
        return groups;
    }

    private void closeNamingEnumeration(NamingEnumeration<?> enumeration) {
        try {
            if (Objects.nonNull(enumeration)) {
                enumeration.close();
            }
        } catch(NamingException e) {
            e.printStackTrace();
        }
    }

    private SearchControls getSearchControls(String[] attrs) {
        return new SearchControls(SearchControls.SUBTREE_SCOPE, 0, 0, attrs, true, true);
    }
}
