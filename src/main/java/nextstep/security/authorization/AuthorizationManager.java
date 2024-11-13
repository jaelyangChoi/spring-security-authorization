package nextstep.security.authorization;

import nextstep.security.access.AccessDeniedException;
import nextstep.security.authentication.Authentication;
import org.springframework.lang.Nullable;

import java.util.function.Supplier;

/**
 * 인증 객체(Authentication)와 특정 리소스(T)를 이용해 인가 여부를 결정하는 로직을 구현
 * @param <T>
 *     요청에 따른 인가별 처리 시 요청(request) 정보가 필요하여 HttpServletRequest가 필요
 *     애너테이션을 활용한 인가 처리 시 메서드 정보가 필요하여 MethodInvocation를 활용.
 */
@FunctionalInterface
public interface AuthorizationManager<T> {
    default void verity(Supplier<Authentication> authentication, T object) {
        AuthorizationDecision decision = this.check(authentication, object);
        if (decision != null && !decision.isGranted()) {
            throw new AccessDeniedException("Access denied");
        }
    }

    @Nullable
    AuthorizationDecision check(Supplier<Authentication> authentication, T object);
}
