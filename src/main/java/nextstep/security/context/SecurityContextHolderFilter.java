package nextstep.security.context;

import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class SecurityContextHolderFilter extends GenericFilterBean {
    private final HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        //세션에서 인증 정보를 찾아 SecurityContextHolder 에 set
        SecurityContext context = this.securityContextRepository.loadContext((HttpServletRequest) request);
        SecurityContextHolder.setContext(context);

        chain.doFilter(request, response);

        SecurityContextHolder.clearContext();
    }
}
