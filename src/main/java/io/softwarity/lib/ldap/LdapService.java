package io.softwarity.lib.ldap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.StartTlsResponse;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
public class LdapService {

  private final LdapSearch ldapSearch;

  private static final String[] LDAP_ATTRIBUTES = new String[] {
    "+",
    "1.1",
    "*"
  };

  public LdapService(LdapSearch ldapSearch) {
    this.ldapSearch = ldapSearch;
  }

  /**
   * Get LdapUser from LDAP sans extraction des groupes
   * @param login
   * @param password
   * @return
   */
  public <T extends LdapUser> Mono<T> getLdapUser(LdapConfiguration ldapConf, String login, String password, BiFunction<String, String, T> ldapUserSupplier) {
    return getLdapUser(ldapConf, login, password, ldapUserSupplier, null);
  }
  /**
   * Get LdapUser from LDAP avec extraction des groupes
   * @param login
   * @param password
   * @return
   */
  public <T extends LdapUser> Mono<T> getLdapUser(LdapConfiguration ldapConf, String login, String password, BiFunction<String, String, T> ldapUserSupplier, BiFunction<Collection<String>, T, T> groupConsumer) {
    log.debug("getLdapUser: {}", login);
    boolean extractMemberOfs = Objects.nonNull(groupConsumer);
    return search(ldapConf, login, password, false, extractMemberOfs).map((LdapResult ldapResult) -> {
      T ldapUser = ldapUserSupplier.apply(login, ldapResult.getAttributes().get("mail").iterator().next());
      if (extractMemberOfs) {
        ldapUser = groupConsumer.apply(ldapResult.getGroupNames(), ldapUser);
      }
      return ldapUser;
    }).onErrorResume((Throwable e) -> {
      log.error("Error while getting LDAP user", e);
      return Mono.empty();
    });
  }

  public Mono<LdapResult> getLdapResult(LdapConfiguration ldapConf, String login, String password, boolean extractServerInformations, boolean extractGroupNames) {
    return search(ldapConf, login, password, extractServerInformations, extractGroupNames);
  }

  private Mono<LdapResult> search(LdapConfiguration ldapConf, String login, String password, boolean extractServerInformations, boolean extractGroupNames) {
    String searchUser = login;
    String w = password;
    String url = ldapConf.getUri(); // ldapuri protocol://host:port
    String b = ldapConf.getBaseDN(); // Use searchbase as the starting point for the search instead of the default.
    boolean zz = ldapConf.isZz(); // Issue StartTLS (Transport Layer Security) extended operation. If you use -ZZ, the command will require the operation to be successful.
    String filter = ldapConf.getFilter(); // filter
    String userDnPattern = ldapConf.getBindDN(); // userDnPattern
    String cert = ldapConf.getCert();
    String D = ldapSearch.createBindPrincipal(searchUser, userDnPattern); // Use the Distinguished Name binddn to bind to the LDAP directory. For SASL binds, the server is expected to ignore this value.
    InitialLdapContext context = null;
    StartTlsResponse tls = null;
    try {
      context = ldapSearch.initContext(url);
      if (zz) {
        tls = ldapSearch.addZZOption(context, cert);
      }
      if (url.toLowerCase().startsWith("ldaps")) {
        MySSLSocketFactory.addCert("ldap", cert);
        context.addToEnvironment("java.naming.ldap.factory.socket", MySSLSocketFactory.class.getName());
      }

      ldapSearch.connect(context, D, w);
      SearchResult searchResult = ldapSearch.searchForBaseDn(context, b, filter, new String[] { login }); // Fetch all data from context
      DirContext dirContext = (DirContext) searchResult.getObject();

      LdapResult ldapResult = new LdapResult();
      if(extractServerInformations) {
        ldapResult.setInformations(getServerInformationFromContext(context, LDAP_ATTRIBUTES));
      }
      ldapResult.setAttributes(getAttributes(dirContext));
      if (extractGroupNames) {
        ldapResult.setGroupNames(ldapSearch.getGroupNames(dirContext, String::new)); // Fetch all memberOf recursively
      }
      return Mono.just(ldapResult);
    } catch (Throwable e) {
      return Mono.error(e);
    } finally {
      closeObject(tls);
      closeObject(context);
    }
  }

  private Map<String, Collection<String>> getAttributes(DirContext attributesForBaseDn) throws NamingException {
    return getAttributes(attributesForBaseDn.getAttributes(""));
  }

  private Map<String, Collection<String>> getServerInformationFromContext(InitialLdapContext context, String... options) throws NamingException {
    return getAttributes(context.getAttributes("", options));
  }

  private Map<String, Collection<String>> getAttributes(Attributes attrs) throws NamingException {
    Map<String, Collection<String>> attributes = new HashMap<String, Collection<String>>();
    NamingEnumeration<? extends Attribute> all = attrs.getAll();
    while (all.hasMore()) {
      Attribute attribute = all.next();
      NamingEnumeration<?> all1 = attribute.getAll();
      while (all1.hasMore()) {
        Object o = all1.next();
        if (!attributes.containsKey(attribute.getID())) {
          attributes.put(attribute.getID(), new ArrayList<>());
        }
        attributes.get(attribute.getID()).add(String.format("%s", o));
      }
    }
    return attributes;
  }

  private void closeObject(Object o) {
    if (Objects.isNull(o)) return;
    try {
      o.getClass().getMethod("close").invoke(o);
    } catch (Throwable ioe) {
    }
  }
}
