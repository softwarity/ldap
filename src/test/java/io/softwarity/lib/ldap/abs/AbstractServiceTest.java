package io.softwarity.lib.ldap.abs;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;

public abstract class AbstractServiceTest {
    /**
   * Récupérer le chemin absolu du fichier LDIF
   * 
   * @param resourceName
   * @return
   */
  public static String getPath(String resourceName) {
    return getFile(resourceName).getAbsolutePath();
  }

  public static File getFile(String resourceName) {
    URL url = AbstractServiceTest.class.getClassLoader().getResource(resourceName);
    if (url == null) {
      throw new IllegalStateException(resourceName + " not found in resources");
    }
    File file = new File(url.getFile());
    return file;
  }

  public static String getCert(String resourceName) {
    StringBuilder content = new StringBuilder();
    System.out.println(AbstractServiceTest.class.getClassLoader().getResource(resourceName));
    try (InputStream inputStream = AbstractLocalServiceTest.class.getClassLoader().getResourceAsStream(resourceName); BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
      String line;
      while ((line = reader.readLine()) != null) {
        content.append(line).append("\n");
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
    return content.toString();
  }

}
