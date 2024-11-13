package nextstep.security.authorization.methodSecurity;

import nextstep.security.authentication.Authentication;
import nextstep.security.authorization.AuthorizationDecision;
import nextstep.security.authorization.AuthorizationManager;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.support.AopUtils;

import java.lang.reflect.Method;
import java.util.function.Supplier;

public class SecuredAuthorizationManager implements AuthorizationManager<MethodInvocation> {
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authenticationSupplier, MethodInvocation methodInvocation) {
        Authentication authentication = authenticationSupplier.get();

        String authorities = getAuthorities(methodInvocation);

        boolean hasRequiredRole = authentication.getAuthorities().stream()
                .anyMatch(role -> role.equals(authorities));

        if (!hasRequiredRole) {
            return new AuthorizationDecision(false);
        }

        return new AuthorizationDecision(true);
    }

    private String getAuthorities(MethodInvocation methodInvocation) {
        Method method = methodInvocation.getMethod();
        Object target = methodInvocation.getThis();
        Class<?> targetClass = (target != null) ? target.getClass() : null;

        return resolveAuthorities(method, targetClass);
    }

    private String resolveAuthorities(Method method, Class<?> targetClass) {
        Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
        Secured secured = specificMethod.getAnnotation(Secured.class);
        return (secured != null) ? secured.value() : null;
    }
}
