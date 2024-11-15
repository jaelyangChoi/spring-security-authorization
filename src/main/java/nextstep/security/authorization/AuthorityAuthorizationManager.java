package nextstep.security.authorization;

import lombok.RequiredArgsConstructor;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.authentication.Authentication;

import java.util.Set;
import java.util.function.Supplier;

@RequiredArgsConstructor
public class AuthorityAuthorizationManager<T> implements AuthorizationManager<T> {

    private final RoleHierarchy roleHierarchy;
    private final String authority;

    @Override
    public AuthorizationDecision check(Authentication authentication, T object) {
        boolean isGranted = isGranted(authentication, authority);
        return new AuthorizationDecision(isGranted);
    }

    private boolean isGranted(Authentication authentication, String authority) {
        Set<String> reachableGrantedAuthorities = roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
        return reachableGrantedAuthorities.contains(authority);
    }
}
