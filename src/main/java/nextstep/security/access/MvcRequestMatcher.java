package nextstep.security.access;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpMethod;

import javax.servlet.http.HttpServletRequest;

@AllArgsConstructor
@Getter
public class MvcRequestMatcher implements RequestMatcher {
    private HttpMethod method;
    private String pattern;

    @Override
    public boolean matches(HttpServletRequest request) {
        if (method != null && !method.name().equals(request.getMethod())) {
            return false;
        }
        return request.getRequestURI().equals(pattern);
    }
}
