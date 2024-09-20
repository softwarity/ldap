package io.softwarity.lib.ldap.models;

import java.util.Collection;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@NoArgsConstructor
@ToString
public class LdapUser {
  private String username;
  private String fullname;
  private String email;
  private Collection<String> memberOf;

  public LdapUser(String username, String email) {
    this.setUsername(username);
    this.setEmail(email);
  }
}
