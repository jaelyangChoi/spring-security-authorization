package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;
import org.springframework.lang.Nullable;

/**
 * 인증 객체(Authentication)와 특정 리소스(T)를 이용해 인가 여부를 결정하는 로직
 * object – the T object to check (HttpServletRequest, MethodInterceptor, MethodInvocation 등)
 */
@FunctionalInterface
public interface AuthorizationManager<T> {

    @Nullable
    AuthorizationDecision check(Authentication authentication, T object);
}
