package io.softwarity.lib.ldap;

import java.util.Collection;
import java.util.Map;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LdapResult {
  Map<String, Collection<String>> informations;
  Map<String, Collection<String>> attributes;
  Collection<String> groupNames;
}
