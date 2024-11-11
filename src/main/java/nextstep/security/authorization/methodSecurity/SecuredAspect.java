package nextstep.security.authorization.methodSecurity;

import nextstep.security.access.AccessDeniedException;
import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;
import nextstep.security.context.SecurityContextHolder;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;

import java.lang.reflect.Method;

@Aspect
public class SecuredAspect {

    @Before("@annotation(nextstep.security.authorization.methodSecurity.Secured)")
    public void checkSecured(JoinPoint joinPoint) throws NoSuchMethodException {
        //메소드에 붙은 애노테이션에서 접근 허용 권한 가져오기
        Method method = getMethodFromJointPoint(joinPoint);
        String permittedAuthority = method.getAnnotation(Secured.class).value();

        //사용자의 권한 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        //권한 검사 - 없을 시 예외 발생
        if (authentication == null)
            throw new AuthenticationException("Authentication required");
        if (!authentication.getAuthorities().contains(permittedAuthority)) {
            throw new AccessDeniedException("Access denied");
        }
    }

    private Method getMethodFromJointPoint(JoinPoint joinPoint) throws NoSuchMethodException {
        Class<?> targetClass = joinPoint.getTarget().getClass();
        String methodName = joinPoint.getSignature().getName();
        Class<?>[] parameterTypes = ((MethodSignature) joinPoint.getSignature()).getParameterTypes();

        return targetClass.getMethod(methodName, parameterTypes);

    }
}
