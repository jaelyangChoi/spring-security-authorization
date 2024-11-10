package nextstep.security.authentication;

import java.util.HashSet;
import java.util.Set;

public class UsernamePasswordAuthenticationToken implements Authentication {

    private final Object principal;
    private final Object credentials;
    private final boolean authenticated;
    private final Set<String> roles;

    private UsernamePasswordAuthenticationToken(Object principal, Object credentials, boolean authenticated) {
        this.principal = principal;
        this.credentials = credentials;
        this.authenticated = authenticated;
        this.roles = new HashSet<>();
    }

    private UsernamePasswordAuthenticationToken(Object principal, Object credentials, boolean authenticated, Set<String> roles) {
        this.principal = principal;
        this.credentials = credentials;
        this.authenticated = authenticated;
        this.roles = roles;
    }

    public static UsernamePasswordAuthenticationToken unauthenticated(String principal, String credentials) {
        return new UsernamePasswordAuthenticationToken(principal, credentials, false);
    }


    public static UsernamePasswordAuthenticationToken authenticated(String principal, String credentials, Set<String> roles) {
        return new UsernamePasswordAuthenticationToken(principal, credentials, true, roles);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public Set<String> getAuthorities() {
        return roles;
    }
}
