package io.softwarity.lib.ldap.abs;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class AbstractOpenLdapTest extends AbstractContainerServiceTest {
  protected static String ADMIN_PWD = "adminpassword";
  private static GenericContainer<?> ldapContainer;

  @BeforeAll
  @SuppressWarnings("resource")
  public static void setUp() {
    ldapContainer = new GenericContainer<>(DockerImageName.parse("osixia/openldap:latest"))
        .withEnv("LDAP_ORGANISATION", "Example Inc.")
        .withEnv("LDAP_DOMAIN", "example.com")
        .withEnv("LDAP_BASE_DN", "dc=example,dc=com")
        .withEnv("LDAP_ADMIN_PASSWORD", ADMIN_PWD)
        .withEnv("LDAP_TLS", "false")
        .withLogConsumer(new Slf4jLogConsumer(log))
        .withExposedPorts(389, 636)
        .withFileSystemBind(getPath("openldap"), "/container/service/slapd/assets/config/bootstrap/ldif/custom",
            BindMode.READ_ONLY)
        // .withFileSystemBind(getPath("other"), "/tmp/custom", BindMode.READ_ONLY)
        .withCommand("--copy-service") // , "--loglevel", "debug")
        .waitingFor(Wait.forLogMessage(".*slapd starting.*", 1)); // Attendre que le serveur soit prêt
    ldapContainer.start();
  }

  @AfterAll
  public static void tearDown() {
    if (ldapContainer != null) {
      log.info("Stopping LDAP container");
      ldapContainer.stop();
    }
  }

  @Override
  protected GenericContainer<?> getContainer() {
    return ldapContainer;
  }
}
