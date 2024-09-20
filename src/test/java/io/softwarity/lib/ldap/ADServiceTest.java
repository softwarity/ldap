package io.softwarity.lib.ldap;

import javax.naming.NamingException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import io.softwarity.lib.ldap.abs.AbstractADTest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Disabled
public class ADServiceTest extends AbstractADTest {

  private String LDAPSEARCH_CMD = "ldapsearch -H ldap://%s -ZZ -o tls_reqcert=never -x -D \"%s\" -y \"/tmp/password-file\" -b \"%s\" \"%s\" \"*\" \"memberOf\"";
  private String ADMIN_DN = "cn=Administrator,cn=Users,dc=example,dc=com";
  private String BASE_DN = "dc=example,dc=com";
  private String OBJECT_CLASS_ALL = "objectclass=*";

  String IP;

  String[] hhfGrps = new String[] { "CN=Users,CN=Builtin,DC=hhome,DC=fr", "CN=Account Operators,CN=Builtin,DC=hhome,DC=fr" };


  public void init() {
    String host = getContainerDns();
    IP = getContainerIp();
    // Ajouter une entrée dans /etc/hosts
    String addHostEntryCommand = String.format("echo \"%s %s\" >> /etc/hosts", IP, host);
    execCommandInContainer("Add host entry", addHostEntryCommand, out -> {
      System.out.println(out);
    }, err -> {
      Assertions.fail(err);
    });
    // Créer un fichier contenant le mot de passe
    String createPasswordCommand = String.format("echo \"%s\" > /tmp/password-file", ADMIN_PWD);
    execCommandInContainer("Create password file", createPasswordCommand, out -> {
      System.out.println(out);
    }, err -> {
      System.err.println(err);
    });
    // Modifier les permissions du fichier pour qu'il soit lisible uniquement par
    // l'utilisateur actuel
    String chmodCommand = String.format("chmod 600 /tmp/password-file");
    execCommandInContainer("Made file read only", chmodCommand, out -> {
      System.out.println(out);
    }, err -> {
      System.err.println(err);
    });
    String showPasswordCommand = String.format("cat /tmp/password-file");
    execCommandInContainer("Show password", showPasswordCommand, out -> {
      System.out.println(out);
    }, err -> {
      System.err.println(err);
    });
  }

  @Test
  @Disabled
  public void checkIndex() {
    // Vérifier la connectivité au serveur LDAP en utilisant l'adresse IP
    // directement
    // String testLdapCommand = String.format("ldapsearch -x -H ldaps://%s -LLL -s base -b \"\" \"%s\" -d 1 -ZZ -o tls_reqcert=never", ip, OBJECT_CLASS_ALL);
    // execCommandInContainer("Test LDAP connectivity", testLdapCommand, out -> {
    //   System.out.println("LDAP server is up and running");
    //   System.out.println(out);
    // }, err -> {
    //   System.err.println("Failed to connect to LDAP server");
    //   Assertions.fail(err);
    // });

    String checkIndexCommand = String.format("ldapsearch -H ldap://%s -x -b \"cn=Subschema\" -y \"/tmp/password-file\" -D \"%s\" -ZZ -o tls_reqcert=never \"%s\"", IP, ADMIN_DN, OBJECT_CLASS_ALL);
    execCommandInContainer("Check the index", checkIndexCommand, out -> {
      System.out.println(out);
    }, err -> {
      System.err.println(err);
    });
  }

  @Test
  // @Disabled
  public void testAdminCommand() {
    init();
    showSambaVersion();
    String command = String.format(LDAPSEARCH_CMD, IP, "Administrator", BASE_DN, OBJECT_CLASS_ALL);
    execCommandInContainer("Athentication with admin user and get all object", command, out -> {
      System.out.println(out);
    }, err -> {
      Assertions.fail(err);
    });
  }


  // @Test
  public void listAcls() {
    // String command = "ldapsearch -Y EXTERNAL -H ldapi:/// -b
    // \"olcDatabase={1}mdb,cn=config\" -LLL olcAccess";
    // execCommandInContainer("Check the acls", command, out -> {
    // System.out.println(out);
    // }, err -> {
    // // Assertions.fail(err);
    // });
  }

  // @Test
  public void checkMemberOfOverlay() {
    // String command = "ldapsearch -Y EXTERNAL -H ldapi:/// -b \"cn=config\" -s sub
    // \"(objectClass=olcOverlayConfig)\"";
    // execCommandInContainer("Check the memberOf mapping", command, out -> {
    // System.out.println(out);
    // }, err -> {
    // // Assertions.fail(err);
    // });
  }

  // @Test
  public void testHhfUserCommand() {
    // String command = "ldapsearch -x -ZZ -H ldap://ldap.hhome.fr:389 -D
    // \"HHOME\\hhf\" -w \"aZ1eR2tY3@hhf\" -b \"DC=hhome,DC=fr\" \"name=hhf\"";
    // int res = executeBashCommand("Authentication with HHOME\\hhf", command, out
    // -> {
    // System.out.println("'"+out+"'");
    // //
    // }, err -> {
    // System.out.println("'"+err+"'");
    // });
    // assert(res) == 0;
  }

  // @Test
  public void testMemberCommand() {
    // searchMember("CN=hhf,CN=Users,DC=hhome,DC=fr", hhfGrps);
    // searchMember("CN=Builtin,DC=hhome,DC=fr", "dn:
    // CN=Users,CN=Builtin,DC=hhome,DC=fr");
  }

  private void searchMember(String search, String... expecteds) {
    // String command = "ldapsearch -x -ZZ -H ldap://ldap.hhome.fr:389 -D
    // \"HHOME\\hhf\" -w \"aZ1eR2tY3@hhf\" -b \"DC=hhome,DC=fr\"
    // \"member="+search+"\" | grep dn:";
    // List<String> out = new ArrayList<>();
    // int res = executeBashCommand("Authentication with HHOME\\hhf and check member
    // for him", command, line -> {
    // System.out.println("'"+line+"'");
    // out.add(line.replaceFirst("dn: ", ""));
    // }, err -> {
    // System.out.println(err);
    // });
    // assert(res) == 0;
    // for (String expected : expecteds) {
    // assertTrue(out.contains(expected));
    // }
  }

  // @Test
  public void testGetLdapUser() throws NamingException {
    // String cert = getCert("hhome.fr_ssl_certificate_INTERMEDIATE.cer");

    // String ldapUrl = "ldap://ldap.hhome.fr:389";
    // LdapConfiguration ldapConf = new LdapConfiguration();
    // ldapConf.setUri(ldapUrl);
    // ldapConf.setBaseDN("DC=hhome,DC=fr");
    // ldapConf.setBindDN("HHOME\\{0}");
    // ldapConf.setFilter("name=hhf");
    // ldapConf.setZz(true);
    // ldapConf.setCert(cert);
    // ldapConf.setIgnoreCertHostname(true);

    // LdapService ldapService = new LdapService();
    // Mono<LdapUser> ldapUserMono = ldapService.getLdapUser(ldapConf, "hhf",
    // "aZ1eR2tY3@hhf", (login, ldapResult) -> {
    // // String email = ldapResult.getAttributes().get("mail").iterator().next();
    // // Collection<String> memberOf = ldapResult.getAttributes().get("memberOf");
    // LdapUser u = new LdapUser(login, "");
    // // u.setMemberOf(memberOf);
    // return u;
    // });

    // LdapUser ldapUser = ldapUserMono.block();
    // Assertions.assertNotNull(ldapUser);
    // System.out.println("User: " + ldapUser.getUsername() + ", Email: " +
    // ldapUser.getEmail());
    // for (String expected : hhfGrps) {
    // assertTrue(ldapUser.getMemberOf().contains(expected));
    // }
  }
}
