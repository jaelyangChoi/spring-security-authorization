package nextstep.security.userdetails;

import java.util.Set;

public interface UserDetails {
    String getUsername();

    String getPassword();

    Set<String> getRoles();
}
