package io.softwarity.lib.ldap.abs;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AbstractADTest extends AbstractContainerServiceTest {
  private static  GenericContainer<?> adContainer;
  protected static String ADMIN_PWD = "Password123!";

  /**
   * TZ - Time zone according to IANA's time zone database, e.g. Europe/Amsterdam, defaults to UTC.
   * REALM - Kerberos realm, the uppercase version of the AD DNS domain, defaults to SAMDOM.EXAMPLE.COM.
   * DOMAIN - NetBIOS domain name (workgroup), single word up to 15 characters without a dot, defaults to SAMDOM.
   * ADMINPASS - Domain administrator password, needs to match complexity requirements, defaults to Passw0rd.
   * INSECURE_LDAP - Set to true to allow simple LDAP binds over unencrypted connections, defaults to false.
   * INSECURE_PASSWORDSETTINGS - Set to true to disable ADMINPASS complexity requirements, defaults to false.
   * SSH_AUTHORIZED_KEYS - SSH public key(s) to enable SSH access to the container, e.g. for complex scenarios.
   * SERVER_SERVICES - Override option for the services⁠ that the Samba daemon will run, defaults to ldap cldap.
   */
  @SuppressWarnings("resource")
  public static void setUp() {
    adContainer = new GenericContainer<>(DockerImageName.parse("smblds/smblds:latest"))
      .withEnv("DOMAIN", "example.com")
      .withEnv("ADMINPASS", ADMIN_PWD)
      .withEnv("INSECURE_LDAP", "false")
      .withEnv("INSECURE_PASSWORDSETTINGS", "true")
      .withLogConsumer(new Slf4jLogConsumer(log))
      .withExposedPorts(389, 636)
      .waitingFor(Wait.forLogMessage(".*TLS self-signed keys generated OK.*", 1));
    adContainer.start();
  }

  @AfterAll
  public static void tearDown() {
    if (adContainer != null) {
      log.info("Stopping AD container");
      // adContainer.stop();
    }
  }

  @Override
  protected GenericContainer<?> getContainer() {
    return adContainer;
  }

  protected void showSambaVersion() {
    // Récupérer l'adresse IP du conteneur
    String sambaVersionCommand = "samba --version";
    execCommandInContainer("", sambaVersionCommand, out -> {
        System.out.println(out);
    }, err -> {
        Assertions.fail(err);
    });
  }

  protected String getContainerIp() {
    // Récupérer l'adresse IP du conteneur
    String getIpCommand = "ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1";
    final String[] ips = new String[1];
    execCommandInContainer("Get IP", getIpCommand, out -> {
        ips[0] = out.trim();
    }, err -> {
        Assertions.fail(err);
    });
    return ips[0];
  }

  protected String getContainerDns() {
    // Récupérer le DNS du conteneur
    String getDnsCommand = "hostname -f";
    final String[] dns = new String[1];
    execCommandInContainer("Get DNS", getDnsCommand, out -> {
        dns[0] = out.trim();
    }, err -> {
        Assertions.fail(err);
    });
    return String.format("%s.samdom.example.com", dns[0].split("\\.")[0].toUpperCase());  
  }
}