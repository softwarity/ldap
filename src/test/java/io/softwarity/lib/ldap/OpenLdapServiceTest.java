package io.softwarity.lib.ldap;

import java.util.Arrays;
import java.util.Collection;

import javax.naming.NamingException;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import io.softwarity.lib.ldap.abs.AbstractOpenLdapTest;
import io.softwarity.lib.ldap.models.LdapUser;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

@Slf4j
public class OpenLdapServiceTest extends AbstractOpenLdapTest {
  private String GROUP_SEARCH_FILTER = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=group))";
  
  private String LDAPSEARCH_CMD = "ldapsearch -x -D \"%s\" -w \"%s\" -b \"%s\" \"%s\" \"*\" \"memberOf\"";

  private String ADMIN_DN = "cn=admin,dc=example,dc=com";
  private String UID_0 = "uid={0}";
  private String USER_BIND_DN = UID_0 + ",ou=users,dc=example,dc=com";
  private String BAD_USER_DN = USER_BIND_DN.replace("{0}", "unknown");
  private String JOHNDOE_DN = USER_BIND_DN.replace("{0}", "johndoe");
  private String JANEDOE_DN = USER_BIND_DN.replace("{0}", "janedoe");
  private String USER_PWD = "password";
  private String DEV_DN = "cn=developer,ou=groups,dc=example,dc=com";
  private String FE_DN = "cn=frontend,ou=groups,dc=example,dc=com";
  private String BE_DN = "cn=backend,ou=groups,dc=example,dc=com";
  private String DEVOPS_DN = "cn=devops,ou=groups,dc=example,dc=com";
  private String OP_DN = "cn=operator,ou=groups,dc=example,dc=com";
  private String BASE_DN = "dc=example,dc=com";
  private String OBJECT_CLASS_ALL = "objectclass=*";

  private LdapService ldapService = new LdapService();

  @Test
  @Disabled
  public void showLdifFilesFolder() {
    Collection<String> files = Arrays.asList("01-config-password.ldif", "02-security.ldif", "03-memberOf.ldif", "04-refint.ldif", "05-index.ldif");
    files.forEach(file -> {
      String command = String.format("cat /container/service/slapd/assets/config/bootstrap/ldif/%s", file);
      execCommandInContainer("Just show the ldif files in folder", command, out -> {
        System.out.println(out);
      }, err -> {
        Assertions.fail(err);
      });
    });
  }

  @Test
  @Disabled
  public void showCustomLdifFolder() {
    String command = "ls -lta /container/service/slapd/assets/config/bootstrap/ldif/custom";
    String expected = "init.ldif";
    execCommandInContainer("Just list the ldif files in custom folder", command, out -> {
      System.out.println(out);
      Assertions.assertThat(out).contains(expected).withFailMessage(String.format("'%s' not found in custom folder", expected));
    }, err -> {
      Assertions.fail(err);
    });

  }

  @Test
  @Disabled
  public void checkIndex() {
    String command = "ldapsearch -Y EXTERNAL -H ldapi:/// -b \"olcDatabase={1}mdb,cn=config\" -LLL olcDbIndex";
    execCommandInContainer("Check the index", command, out -> {
      System.out.println(out);
    }, err -> {
      // Assertions.fail(err);
    });
  }

  @Test
  @Disabled
  public void listAcls() {
    String command = "ldapsearch -Y EXTERNAL -H ldapi:/// -b \"olcDatabase={1}mdb,cn=config\" -LLL olcAccess";
    execCommandInContainer("Check the acls", command, out -> {
      System.out.println(out);
    }, err -> {
      // Assertions.fail(err);
    });
  }

  @Test
  @Disabled
  public void checkMemberOfOverlay() {
    String command = "ldapsearch -Y EXTERNAL -H ldapi:/// -b \"cn=config\" -s sub \"(objectClass=olcOverlayConfig)\"";
    execCommandInContainer("Check the memberOf mapping", command, out -> {
      System.out.println(out);
    }, err -> {
      // Assertions.fail(err);
    });
  }

  @Test
  @Disabled
  public void checkGroups() {
    String command = String.format("ldapsearch -x -D \"cn=admin,dc=example,dc=com\" -w \"adminpassword\" -b \"ou=groups,dc=example,dc=com\" \"%s\" uniqueMember memberOf", GROUP_SEARCH_FILTER);
    execCommandInContainer("check groups", command, out -> {
      System.out.println(out);
    }, err -> {
      Assertions.fail(err);
    });
  }

  @Test
  @Disabled
  public void whoIAmCommand() {
    String command = String.format("ldapwhoami -x -H ldap://localhost:389 -D \"%s\" -w \"password\"", JOHNDOE_DN);
    String expected = "dn:" + JOHNDOE_DN;
    execCommandInContainer("ldapwhoami command", command, out -> {
      Assertions.assertThat(out).isEqualTo(expected).withFailMessage(String.format("'%s' didn't contain expected '%s'", out, expected));
    }, err -> {
      Assertions.fail(err);
    });
  }

  @Test
  @Disabled
  public void testAdminCommand() {
    String command = String.format(LDAPSEARCH_CMD, ADMIN_DN, ADMIN_PWD, BASE_DN, OBJECT_CLASS_ALL);
    execCommandInContainer("Athentication with admin user and get all object", command, out -> {
      System.out.println(out);
    }, err -> {
      Assertions.fail(err);
    });
  }

  @Test
  // @Disabled
  public void testJohnDoeLoginCommand() {
    String command = String.format(LDAPSEARCH_CMD, JOHNDOE_DN, USER_PWD, BASE_DN, UID_0.replace("{0}", "johndoe"));
    execCommandInContainer("Athentication with johndoe user, get memberOf BE, FE and OP groups", command, out -> {
      // System.out.println(out);
    }, err -> {
      Assertions.fail(err);
    }, (map, mapCollection) -> {
      String mail = map.get("mail");
      Assertions.assertThat(mail).isNotNull().withFailMessage("johndoe mail should not be null");
      Assertions.assertThat(mail).isEqualTo("johndoe@example.com").withFailMessage("mail should be johndoe@example.com");
      // Assertions.assertThat(mapCollection.get("memberOf")).contains(DEV_DN).withFailMessage("memberOf should contain '%s'", DEV_DN); // pas d'heritage de group
      Assertions.assertThat(mapCollection.get("memberOf")).contains(BE_DN).withFailMessage("memberOf should contain '%s'", BE_DN);
      Assertions.assertThat(mapCollection.get("memberOf")).contains(FE_DN).withFailMessage("memberOf should contain '%s'", FE_DN);
      Assertions.assertThat(mapCollection.get("memberOf")).contains(OP_DN).withFailMessage("memberOf should contain '%s'", OP_DN);
    });
    command = String.format(LDAPSEARCH_CMD, JOHNDOE_DN, USER_PWD, FE_DN, OBJECT_CLASS_ALL);
    execCommandInContainer("Look for who own FE group", command, out -> {
      // System.out.println(out);
    }, err -> {
      Assertions.fail(err);
    }, (map, mapCollection) -> {
      Assertions.assertThat(mapCollection.get("memberOf")).contains(DEV_DN).withFailMessage("memberOf should contain '%s'", DEV_DN);
    });
    command = String.format(LDAPSEARCH_CMD, JOHNDOE_DN, USER_PWD, BE_DN, OBJECT_CLASS_ALL);
    execCommandInContainer("Look for who own BE group", command, out -> {
      // System.out.println(out);
    }, err -> {
      Assertions.fail(err);
    }, (map, mapCollection) -> {
      Assertions.assertThat(mapCollection.get("memberOf")).contains(DEV_DN).withFailMessage("memberOf should contain '%s'", DEV_DN);
    });
  }

  @Test
  // @Disabled
  public void testJaneDoeLoginCommand() {
    String command = String.format(LDAPSEARCH_CMD, JANEDOE_DN, USER_PWD, JANEDOE_DN, UID_0.replace("{0}", "janedoe"));
    execCommandInContainer("Athentication with janedoe user", command, out -> {
    }, err -> {
      Assertions.fail(err);
    }, (map, mapCollection) -> {
      String mail = map.get("mail");
      Assertions.assertThat(mail).isNotNull().withFailMessage("janedoe mail should not be null");
      Assertions.assertThat(mail).isEqualTo("janedoe@example.com").withFailMessage("mail should be janedoe@example.com");
      Assertions.assertThat(mapCollection.get("memberOf")).contains(OP_DN).withFailMessage("memberOf should contain '%s'", OP_DN);
    });
  }

  @Test
  // @Disabled
  public void testGetUpperGroupCommand() {
    String command = String.format(LDAPSEARCH_CMD, JOHNDOE_DN, USER_PWD, FE_DN, GROUP_SEARCH_FILTER);
    execCommandInContainer("Look for who own FE group", command, out -> {
      // System.out.println(out);
    }, err -> {
      Assertions.fail(err);
    }, (map, mapCollection) -> {
      Assertions.assertThat(mapCollection.get("memberOf")).contains(DEV_DN).withFailMessage("memberOf should contain '%s'", DEV_DN);
    });
    // John doe n'est pas membre de devops donc il y accede pas
    command = String.format(LDAPSEARCH_CMD, JOHNDOE_DN, USER_PWD, DEVOPS_DN, GROUP_SEARCH_FILTER);
    execCommandInContainer("Look for who own DEVOPS group", command, out -> {
      // System.out.println(out);
    }, err -> {
      Assertions.fail(err);
    }, (map, mapCollection) -> {
      Assertions.assertThat(mapCollection.get("memberOf")).withFailMessage("memberOf should be null because john doe is not member of devops").isNull();
    });
    // Jane doe est membre de devops donc elle y accede
    command = String.format(LDAPSEARCH_CMD, JANEDOE_DN, USER_PWD, DEVOPS_DN, GROUP_SEARCH_FILTER);
    execCommandInContainer("Look for who own DEVOPS group", command, out -> {
      System.out.println(out);
    }, err -> {
      Assertions.fail(err);
    }, (map, mapCollection) -> {
      Assertions.assertThat(mapCollection.get("memberOf")).contains(DEV_DN).withFailMessage("memberOf should contain '%s'", DEV_DN);
    });
  }

  @Test
  // @Disabled
  public void testLoginFailCommand() {
    String command = String.format(LDAPSEARCH_CMD, BAD_USER_DN, USER_PWD, BASE_DN, "");
    execCommandInContainer("Athentication fail", command, out -> {
      Assertions.fail(out);
    }, err -> {
      Assertions.assertThat(err).contains("Invalid credentials").withFailMessage("The auth should be failed, but return '%s'", err);
    });
  }

  @Test
  // @Disabled
  public void testGetLdapUser() throws NamingException {
    log.info("==============================================");
    log.info("Test ldapService.getLdapUser");
    log.info("==============================================");
    LdapConfiguration ldapConf = getLdapConf();

    Mono<LdapUser> ldapUserMono = ldapService.getLdapUser(ldapConf, "johndoe", USER_PWD, (login, ldapResult) -> {
      String mail = ldapResult.getString("mail");
      String fullname = ldapResult.getString("cn");
      Collection<String> memberOf = ldapResult.getCollection("memberOf");
      LdapUser u = new LdapUser(login, mail);
      u.setFullname(fullname);
      u.setMemberOf(memberOf);
      return u;
    });
    StepVerifier.create(ldapUserMono).consumeNextWith(ldapUser -> {
      Assertions.assertThat(ldapUser.getUsername()).isEqualTo("johndoe").withFailMessage("username should be johndoe");
      Assertions.assertThat(ldapUser.getEmail()).isEqualTo("johndoe@example.com").withFailMessage("email should be johndoe@example.com");
      Assertions.assertThat(ldapUser.getFullname()).isEqualTo("John Doe").withFailMessage("fullname should be John Doe");
      Assertions.assertThat(ldapUser.getMemberOf()).hasSize(4).withFailMessage("memberOf should have 4 elements");
      Assertions.assertThat(ldapUser.getMemberOf()).contains(DEV_DN).withFailMessage("memberOf should contain '%s'", DEV_DN); // because we resolve the group with memberOf overlay
      Assertions.assertThat(ldapUser.getMemberOf()).contains(FE_DN).withFailMessage("memberOf should contain '%s'", FE_DN);
      Assertions.assertThat(ldapUser.getMemberOf()).contains(BE_DN).withFailMessage("memberOf should contain '%s'", BE_DN);
      Assertions.assertThat(ldapUser.getMemberOf()).contains(OP_DN).withFailMessage("memberOf should contain '%s'", OP_DN);
    }).verifyComplete();
  }

  @Test
  // @Disabled
  public void testFailGetLdapUser() throws NamingException {
    log.info("==============================================");
    log.info("Test ldapService.getLdapUser Fail");
    log.info("==============================================");
    LdapConfiguration ldapConf = getLdapConf();

    Mono<LdapUser> ldapUserMono = ldapService.getLdapUser(ldapConf, "johndoe", USER_PWD + 1, (login, ldapResult) -> {
      return new LdapUser(login, "");
    });
    StepVerifier.create(ldapUserMono)
        .expectErrorMatches(throwable -> throwable instanceof javax.naming.AuthenticationException).verify();
  }

  private LdapConfiguration getLdapConf() {
    String ldapUrl = "ldap://" + getContainer().getHost() + ":" + getContainer().getMappedPort(389);
    LdapConfiguration ldapConf = new LdapConfiguration();
    ldapConf.setUri(ldapUrl);
    ldapConf.setBaseDN(BASE_DN);
    ldapConf.setBindDN(USER_BIND_DN);
    ldapConf.setFilter(UID_0);
    ldapConf.setZz(false);
    return ldapConf;
  }
}
