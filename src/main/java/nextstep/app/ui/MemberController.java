package nextstep.app.ui;

import nextstep.app.domain.Member;
import nextstep.app.domain.MemberRepository;
import nextstep.security.access.AccessDeniedException;
import nextstep.security.authorization.methodSecurity.Secured;
import nextstep.security.authentication.AuthenticationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class MemberController {

    private final MemberRepository memberRepository;

    public MemberController(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @GetMapping("/members")
    public ResponseEntity<List<Member>> list() {
        List<Member> members = memberRepository.findAll();
        return ResponseEntity.ok(members);
    }

    @Secured("ADMIN")
    @GetMapping("/search")
    public ResponseEntity<List<Member>> search() {
        List<Member> members = memberRepository.findAll();
        return ResponseEntity.ok(members);
    }

    //Method Security 로 발생한 예외 처리
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Void> handleAccessDeniedException() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

}
