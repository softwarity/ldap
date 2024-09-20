package io.softwarity.lib.ldap.abs;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class AbstractLocalServiceTest extends AbstractServiceTest {

  protected int executeBashCommand(String description, String command, Consumer<String> consumerOut, Consumer<String> consumerErr) {
    return executeBashCommand(description, command, consumerOut, consumerErr, (map, mapCollection) -> {});
  }

  protected int executeBashCommand(String description, String command, Consumer<String> consumerOut, Consumer<String> consumerErr, BiConsumer<Map<String, String>, Map<String, Collection<String>>> consumerMap) {
    log.info("==============================================");
    log.info(description);
    log.info("==============================================");
    log.info(command);
    log.info("==============================================");
    ProcessBuilder processBuilder = new ProcessBuilder();
    // Utiliser "bash" et "-c" pour exécuter la commande
    processBuilder.command("bash", "-c", command);
    BufferedReader reader = null;
    try {
      Process process = processBuilder.start();
      reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      Map<String, String> map = new HashMap<>();
      Map<String, Collection<String>> mapCollection = new HashMap<>();
      Stream<String> stream = reader.lines().collect(Collectors.toList()).stream(); // Pour consommer la sortie, sinon le process se bloque
      stream.dropWhile(l -> !l.startsWith("dn: CN=hhf")).map(l -> l.trim())
      .takeWhile(l -> !l.startsWith("distinguishedName: CN=hhf")).map(l -> l.trim())
      .filter(l -> !l.isBlank())
      .filter(l -> !l.startsWith("#"))
      .filter(l -> !l.contains("password"))
      .filter(l -> !l.contains("Password"))
      .filter(l -> !l.startsWith("search"))
      .filter(l -> !l.startsWith("result"))
      .filter(l -> l.matches("\\w+:\\s.*"))
      .forEach((String line) -> {
        consumerOut.accept(line.trim());
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
      BufferedReader readerErr = new BufferedReader(new InputStreamReader(process.getErrorStream()));
      readerErr.lines().forEach(consumerErr);
      log.info("==============================================");
      return process.waitFor(10, TimeUnit.SECONDS) ? process.exitValue() : -1;
    } catch (IOException | InterruptedException e) {
      e.printStackTrace();
      return 1;
    } finally {
      if (reader != null) {
        try {
          reader.close();
        } catch (IOException e) {
          e.printStackTrace();
        }
      }
    }
  }
}