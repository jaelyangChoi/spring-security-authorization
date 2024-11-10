package nextstep.app.infrastructure;

import nextstep.app.domain.Member;
import nextstep.app.domain.MemberRepository;
import org.springframework.stereotype.Repository;

import java.util.*;
import java.util.stream.Collectors;

@Repository
public class InmemoryMemberRepository implements MemberRepository {
    public static final Member ADMIN_MEMBER = new Member("a@a.com", "password", "a", "", Set.of("ADMIN"));
    public static final Member USER_MEMBER = new Member("b@b.com", "password", "b", "", Set.of("USER"));
    private static final Map<String, Member> members = new HashMap<>();

    static {
        members.put(ADMIN_MEMBER.getEmail(), ADMIN_MEMBER);
        members.put(USER_MEMBER.getEmail(), USER_MEMBER);
    }

    @Override
    public Optional<Member> findByEmail(String email) {
        return Optional.ofNullable(members.get(email));
    }

    @Override
    public List<Member> findAll() {
        return members.values().stream().collect(Collectors.toUnmodifiableList());
    }

    @Override
    public void save(Member member) {
        members.put(member.getEmail(), member);
    }
}
