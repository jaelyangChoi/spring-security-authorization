package nextstep.security.authorization;

import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.authentication.Authentication;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Authorize HttpServletRequest
 */
public class RequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<HttpServletRequest> {
    private static final AuthorizationDecision DENY = new AuthorizationDecision(false);
    private static final AuthorizationDecision PERMIT = new AuthorizationDecision(true);
    private final Map<RequestURI, String> configAttribute;
    private final RoleHierarchy roleHierarchy;

    public RequestMatcherDelegatingAuthorizationManager(RoleHierarchy roleHierarchy) {
        this.configAttribute = new HashMap<>();
        configAttribute.put(new RequestURI("/members", "GET"), "ADMIN");
        configAttribute.put(new RequestURI("/members/me", "GET"), "USER");
        configAttribute.put(new RequestURI("/search", "GET"), "permitAll");
        configAttribute.put(new RequestURI("/login", "GET"), "permitAll");
        this.roleHierarchy = roleHierarchy;
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authenticationSupplier, HttpServletRequest request) {
        Authentication authentication = authenticationSupplier.get();

        RequestURI requestURI = new RequestURI(request.getRequestURI(), request.getMethod());

        //등록된 경로 외 경로는 아무도 접근할 수 없게 한다.
        if (!configAttribute.containsKey(requestURI)) {
            return DENY;
        }

        String role = configAttribute.get(requestURI);
        //any
        if (role.equals("permitAll")) {
            return PERMIT;
        }

        //특정 권한 확인
        //권한의 계층 구조 적용을 위해서는 RoleHierarchy 객체로부터 authorities를 업데이트 받아야함.
        Set<String> reachableGrantedAuthorities = roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
        if (!role.equals("authenticated") && !reachableGrantedAuthorities.contains(role)) {
            return DENY;
        }
        return PERMIT;
    }

    class RequestURI {
        private final String uri;
        private final String path;

        public RequestURI(String uri, String path) {
            this.uri = uri;
            this.path = path;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RequestURI that = (RequestURI) o;
            return Objects.equals(uri, that.uri) && Objects.equals(path, that.path);
        }

        @Override
        public int hashCode() {
            return Objects.hash(uri, path);
        }

        @Override
        public String toString() {
            return "RequestURI{" +
                    "uri='" + uri + '\'' +
                    ", path='" + path + '\'' +
                    '}';
        }
    }
}
