package io.softwarity.lib.ldap;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@ToString
public class LdapConfiguration {
  // LDAP Uniform Resource Identifier(s)
  String uri;
  // bind DN, use pattern with {0}
  String bindDN;
  // base dn for search
  String baseDN;
  // Start TLS request (-ZZ to require successful response)
  boolean zz;
  // RFC 4515 compliant LDAP search filter
  String filter;
  // Public LDAP Certificat
  String cert;
  // Ignore certificate hostname
  boolean ignoreCertHostname = false;
}
