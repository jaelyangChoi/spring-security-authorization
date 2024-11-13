package nextstep.security.authorization;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@RequiredArgsConstructor
@Getter
@ToString
public class AuthorizationDecision {
    private final boolean granted;
}
