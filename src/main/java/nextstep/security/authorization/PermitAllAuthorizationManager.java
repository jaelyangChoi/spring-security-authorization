package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;

import java.util.function.Supplier;

public class PermitAllAuthorizationManager<T> implements AuthorizationManager<T> {

    @Override
    public AuthorizationDecision check(Authentication authentication, T object) {
        return null;
    }
}
