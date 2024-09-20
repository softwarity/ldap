# ldap

## LDAP Authentication reactor library implementation

This library allow to java project with reactor to authenticate user with LDAP.


### Create LDAP configuration

```java
LdapConfiguration ldapConf = new LdapConfiguration();
    // Define the ldap uri
    ldapConf.setUri("ldap://ldap.example.com");
    // OR for ldaps
    ldapConf.setUri("ldaps://ldap.example.com");
    
    // Define the baseDN
    ldapConf.setBaseDN("dc=example,dc=com");

    // Define the bindDN parametre D in ldapsearch command, use {0} as the login
    ldapConf.setBindDN("EXAMPLE\\{0}"); // AD style, Use bindDN pattern with {0}
    // OR
    ldapConf.setBindDN("uid={0},ou=users,dc=example,dc=com"); // OpenLDAP style, Use bindDN pattern with {0}

    // Define the filter
    ldapConf.setFilter("(uid={0})"); // OpenLDAP filter with {0}
    // OR
    ldapConf.setFilter("(cn={0})"); // OpenLDAP filter with {0}

    // Define if StartTLS (Transport Layer Security) is mandatory
    ldapConf.setZz(true);
    // Define the certificat to use for the LDAP connexion
    ldapConf.setCert("-----BEGIN CERTIFICATE-----\nMIIEqjCCA5KgAwIBAgIQDeD/te......\n-----END CERTIFICATE-----"); // Dont forget \n on each lines
    // OR
    ldapConf.setCertFromResource("path-in-resources/certificat.cer "); 
    // OR
    ldapConf.setCertFromFile(new File("/path/to/certificat.cer"));
    // OR
    try (InputStream inputStream = new FileInputStream(new File("/path/to/certificat.cer"));) {
      ldapConf.setCertFromInputStream(inputStream);
    }
```


### Use the library


```java
private LdapService ldapService = new LdapService();

Mono<LdapUser> ldapUser = ldapService.getLdapUser(ldapConf, "johndoe", "secret", (login, ldapResult) -> {
  String mail = ldapResult.getString("mail");
  String fullname = String.format("%s %s", ldapResult.getString("givenName"), ldapResult.getString("sn"));
  Collection<String> memberOf = ldapResult.getCollection("memberOf");
  LdapUser u = new LdapUser(login, mail);
  u.setFullname(fullname);
  u.setMemberOf(memberOf);
  return u;
});

```
