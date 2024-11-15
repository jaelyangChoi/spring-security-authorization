package nextstep.security.access;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class RequestMatcherEntry<T> {
    private final RequestMatcher requestMatcher;
    private final T entry; //AuthorizationManager. 사용처를 보면 알 수 있다.. 역추적 스킬 습득
}
