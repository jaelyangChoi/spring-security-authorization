package nextstep.security.access;

public class AccessDeniedException extends RuntimeException {
    public AccessDeniedException(String msg) {
        super(msg);
    }
}
