package nextstep.security.access;

import javax.servlet.http.HttpServletRequest;

public class AnyRequestMatcher implements RequestMatcher {
    public static final AnyRequestMatcher INSTANCE = new AnyRequestMatcher();

    @Override
    public boolean matches(HttpServletRequest request) {
        return true;
    }
}
