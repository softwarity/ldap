package io.softwarity.lib.ldap;

import java.util.Objects;
import java.util.function.BiFunction;

import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.StartTlsResponse;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
public class LdapService {

  private final LdapSearch ldapSearch;

  public LdapService() {
    this.ldapSearch = new LdapSearch();
  }

  /**
   * Get T from LDAP
   * 
   * @param login
   * @param password
   * @return
   */
  public <T> Mono<T> getLdapUser(LdapConfiguration ldapConf, String login, String password, BiFunction<String, LdapResult, T> ldapUserSupplier) {
    log.debug("getLdapUser: {}", login);
    return getLdapResult(ldapConf, login, password).map((LdapResult ldapResult) -> {
      return ldapUserSupplier.apply(login, ldapResult);
    });
  }

  public Mono<LdapResult> getLdapResult(LdapConfiguration ldapConf, String login, String password) {
    log.debug("getLdapResult: {}", login);
    return search(ldapConf, login, password);
  }
  
  private Mono<LdapResult> search(LdapConfiguration ldapConf, String login, String password) {
    return Mono.create(sink -> {
      String searchUser = login;
      String w = password;
      String url = ldapConf.getUri(); // ldapuri protocol://host:port
      String b = ldapConf.getBaseDN(); // Use searchbase as the starting point for the search instead of the default.
      boolean zz = ldapConf.isZz(); // Issue StartTLS (Transport Layer Security) extended operation. If you use -ZZ, the command will require the operation to be successful.
      String filter = ldapConf.getFilter(); // filter
      String userDnPattern = ldapConf.getBindDN(); // userDnPattern
      String cert = ldapConf.getCert();
      boolean ignoreCertHostname = ldapConf.isIgnoreCertHostname();
      String D = ldapSearch.createBindPrincipal(searchUser, userDnPattern); // Use the Distinguished Name binddn to bind to the LDAP directory. For SASL binds, the server is expected to ignore this value.
      InitialLdapContext context = null;
      StartTlsResponse tls = null;
      try {
        context = ldapSearch.initContext(url);
        if (zz) { // attention à l'ordre, a voir si on peut ameliorer ca
          tls = ldapSearch.addZZOption(context, cert, ignoreCertHostname);
        }
        if (url.toLowerCase().startsWith("ldaps")) {
          LdapSSLSocketFactory.addCert("ldap", cert);
          context.addToEnvironment("java.naming.ldap.factory.socket", LdapSSLSocketFactory.class.getName());
        }
        
        ldapSearch.connect(context, D, w);
        sink.success(ldapSearch.search(context, D, b, filter, login));
      } catch (Throwable e) {
        sink.error(e);
      } finally {
        closeObject(tls);
        closeObject(context);
      }
    });
  }

  private void closeObject(Object o) {
    if (Objects.isNull(o))
      return;
    try {
      o.getClass().getMethod("close").invoke(o);
    } catch (Throwable ioe) {
    }
  }
}
