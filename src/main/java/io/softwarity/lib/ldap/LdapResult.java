package io.softwarity.lib.ldap;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@ToString
public class LdapResult extends HashMap<String, Collection<String>> {

  /**
   * Retourne la premiere valeur de la collection associee a la cle
   * Si la collection est vide ou n'existe pas, retourne null
   * @param key
   * @return
   */
  public String getFirst(String key) {
    if (containsKey(key)) {
      Collection<String> values = get(key);
      return values.isEmpty() ? null : values.iterator().next();
    }
    return null;
  }

  /**
   * Retourne la premiere valeur de la collection associee a la cle
   * Si la collection est vide ou n'existe pas, retourne ""
   * @param key
   * @return
   */
  public String getString(String key) {
    if (containsKey(key)) {
      Collection<String> values = get(key);
      return values.isEmpty() ? "" : values.iterator().next();
    }
    return "";
  }

  /**
   * Retourne la collection associee a la cle
   * Si la collection n'existe pas retourne une liste vide
   * @param key
   * @return
   */
  public Collection<String> getCollection(String key) {
    if (containsKey(key)) {
      return get(key);
    }
    return Collections.emptyList();
  }
  
  /**
   * Retourne la premiere et unique valeur de la collection associee à la clé
   * Si pas de valeur ou plusieurs, retourne une IllegalStateException
   * @param key
   * @return
   * @throws java.lang.IllegalStateException
   */
  public String getUniq(String key) throws java.lang.IllegalStateException{
    Collection<String> values = get(key);
    if (values.size() != 1) {
      throw new IllegalStateException("The key " + key + " has " + values.size() + " values");
    }
    return values.iterator().next();
  }
}
