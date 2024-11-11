package nextstep.security.authorization;

import lombok.extern.slf4j.Slf4j;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.authentication.Authentication;
import nextstep.security.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class AuthorizationFilter extends GenericFilterBean {

    private final Map<RequestURI, String> configAttribute;
    private final RoleHierarchy roleHierarchy;

    public AuthorizationFilter() {
        this.configAttribute = new HashMap<>();
        configAttribute.put(new RequestURI("/members", "GET"), "ADMIN");
        configAttribute.put(new RequestURI("/members/me", "GET"), "USER");
        configAttribute.put(new RequestURI("/search", "GET"), "permitAll");
        configAttribute.put(new RequestURI("/login", "GET"), "permitAll");
        this.roleHierarchy = new RoleHierarchy("USER < ADMIN");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        RequestURI requestURI = new RequestURI(request.getRequestURI(), request.getMethod());
        log.info(requestURI.toString());

        //등록된 경로 외 경로는 아무도 접근할 수 없게 한다.
        if (!configAttribute.containsKey(requestURI)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        String role = configAttribute.get(requestURI);

        //any
        if (role.equals("permitAll")) {
            filterChain.doFilter(request, response);
            return;
        }

        //인가 체크
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        //권한 없음
        if (authentication == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        //특정 권한 확인
        //권한의 계층 구조 적용을 위해서는 RoleHierarchy 객체로부터 authorities를 업데이트 받아야함.
        Set<String> reachableGrantedAuthorities = roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
        if (!role.equals("authenticated") && !reachableGrantedAuthorities.contains(role)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        filterChain.doFilter(request, response);
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
