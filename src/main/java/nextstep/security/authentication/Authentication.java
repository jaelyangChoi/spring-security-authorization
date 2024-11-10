package nextstep.security.authentication;

import java.util.Collection;
import java.util.Set;

public interface Authentication {

    Object getCredentials();

    Object getPrincipal();

    boolean isAuthenticated();

    Set<String> getAuthorities();

}
