package nextstep.security.authorization;

import lombok.RequiredArgsConstructor;
import nextstep.security.access.RequestMatcher;
import nextstep.security.access.RequestMatcherEntry;
import nextstep.security.authentication.Authentication;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.function.Supplier;

/**
 * Authorize HttpServletRequest
 */
@RequiredArgsConstructor
public class RequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<HttpServletRequest> {
    private static final AuthorizationDecision DENY = new AuthorizationDecision(false);
    private final List<RequestMatcherEntry<AuthorizationManager>> mappings;

    @Override
    public AuthorizationDecision check(Authentication authentication, HttpServletRequest request) {
        //요청에 맞는 AuthorizationManger 를 가져와 인가 처리
        for (RequestMatcherEntry<AuthorizationManager> mapping : mappings) {
            RequestMatcher requestMatcher = mapping.getRequestMatcher();
            if (requestMatcher.matches(request)) {
                AuthorizationManager manager = mapping.getEntry();

                return manager.check(authentication, request);
            }
        }

        return DENY;
    }
}
