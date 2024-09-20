package io.softwarity.lib.ldap;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collector;
import java.util.stream.Collectors;

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
  private String uri;
  // bind DN, use pattern with {0}
  private String bindDN;
  // base dn for search
  private String baseDN;
  // Start TLS request (-ZZ to require successful response)
  private boolean zz;
  // RFC 4515 compliant LDAP search filter
  private String filter;
  // Public LDAP Certificat
  private String cert;
  // Ignore certificate hostname
  private boolean ignoreCertHostname = false;

  public void setCertFromResource(String resourceName) {
    try (InputStream inputStream = LdapConfiguration.class.getClassLoader().getResourceAsStream(resourceName)) {
      setCertFromInputStream(inputStream);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void setCertFromFile(File file) {
    try (InputStream inputStream = new FileInputStream(file);) {
      setCertFromInputStream(inputStream);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void setCertFromInputStream(InputStream inputStream) {
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
      this.cert = reader.lines().collect(Collectors.joining("\n"));
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}


