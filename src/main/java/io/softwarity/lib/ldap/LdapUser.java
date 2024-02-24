package io.softwarity.lib.ldap;

import java.util.Collection;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LdapUser {
  String username;
  String email;
  Collection<String> groupNames;
  Collection<String> profileNames;
}
