package io.softwarity.lib.ldap.abs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class AbstractContainerServiceTest extends AbstractServiceTest {

  protected abstract GenericContainer<?> getContainer();

  @Test
  @Disabled
  public void ldapsearchVersion() {
    String command = "ldapsearch -VV";
    execCommandInContainer("Display ldapsearch version in container", command, out -> {
      System.out.println(out);
    }, err -> {
      System.out.println(err);
    });
  }

  protected void execCommandInContainer(String description, String command, Consumer<String> consumerOut, Consumer<String> consumerErr) {
    execCommandInContainer(description, command, consumerOut, consumerErr, (map, mapCollection) -> {});
  }

  protected void execCommandInContainer(String description, String command, Consumer<String> consumerOut, Consumer<String> consumerErr, BiConsumer<Map<String, String>, Map<String, Collection<String>>> consumerMap) {
    log.info("==============================================");
    log.info(description);
    log.info("==============================================");
    log.info(command);
    log.info("==============================================");
    try {
      Container.ExecResult result = execInContainer("sh", "-c", command);
      String out = result.getStdout();
      if (!out.trim().isEmpty()) {
        consumerOut.accept(out.trim());
      }
      Map<String, String> map = new HashMap<>();
      Map<String, Collection<String>> mapCollection = new HashMap<>();
      out.lines()
          .map(l -> l.trim())
          .filter(l -> !l.isBlank())
          .filter(l -> !l.startsWith("#"))
          .filter(l -> !l.contains("password"))
          .filter(l -> !l.contains("Password"))
          .filter(l -> !l.startsWith("search"))
          .filter(l -> !l.startsWith("result"))
          .filter(l -> l.matches("\\w+:\\s.*"))
          .forEach((String line) -> {
            Pattern p = Pattern.compile("(?<key>\\w+):\\s(?<value>.*)");
            Matcher m = p.matcher(line);
            if (m.matches()) {
              String key = m.group("key");
              String value = m.group("value");
              if (mapCollection.containsKey(key)) {
                mapCollection.get(key).add(value);
              } else if (key.equals("memberOf")) {
                mapCollection.put(key, new ArrayList<>());
                mapCollection.get(key).add(value);
              } else if (map.containsKey(key)) {
                String prev = map.get(key);
                map.remove(key);
                mapCollection.put(key, new ArrayList<>());
                mapCollection.get(key).add(prev);
                mapCollection.get(key).add(value);
              } else {
                map.put(key, value);
              }
            }
          });
      consumerMap.accept(map, mapCollection);
      String err = result.getStderr();
      if (!err.trim().isEmpty()) {
        consumerErr.accept(err.trim());
      }
    } catch (IOException | InterruptedException e) {
      log.error("Failed to search LDAP entries", e);
    }
  }

  protected Container.ExecResult execInContainer(String... command) throws UnsupportedOperationException, IOException, InterruptedException {
    return getContainer().execInContainer(command);
  }
}