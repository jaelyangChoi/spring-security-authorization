package nextstep.app;

import nextstep.app.domain.Member;
import nextstep.app.infrastructure.InmemoryMemberRepository;
import nextstep.security.authentication.Authentication;
import nextstep.security.context.SecurityContextHolder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class BasicAuthTest {
    private static final Member TEST_ADMIN_MEMBER = InmemoryMemberRepository.ADMIN_MEMBER;
    private static final Member TEST_USER_MEMBER = InmemoryMemberRepository.USER_MEMBER;

    @Autowired
    private MockMvc mockMvc;

    @DisplayName("ADMIN 권한을 가진 사용자가 요청할 경우 모든 회원 정보를 조회할 수 있다.")
    @Test
    void request_success_with_admin_user() throws Exception {
        String token = Base64.getEncoder().encodeToString((TEST_ADMIN_MEMBER.getEmail() + ":" + TEST_ADMIN_MEMBER.getPassword()).getBytes());

        ResultActions response = mockMvc.perform(get("/members")
                .header("Authorization", "Basic " + token)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        response.andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.length()").value(2));
    }

    @DisplayName("일반 사용자가 요청할 경우 권한이 없어야 한다.")
    @Test
    void request_fail_with_general_user() throws Exception {
        String token = Base64.getEncoder().encodeToString((TEST_USER_MEMBER.getEmail() + ":" + TEST_USER_MEMBER.getPassword()).getBytes());

        ResultActions response = mockMvc.perform(get("/members")
                .header("Authorization", "Basic " + token)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        response.andExpect(status().isForbidden());
    }

    @DisplayName("사용자 정보가 없는 경우 요청이 실패해야 한다.")
    @Test
    void request_fail_with_no_user() throws Exception {
        String token = Base64.getEncoder().encodeToString(("none" + ":" + "none").getBytes());

        ResultActions response = mockMvc.perform(get("/members")
                .header("Authorization", "Basic " + token)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        response.andExpect(status().isUnauthorized());
    }

    @DisplayName("Invalid한 패스워드로 요청할 경우 실패해야 한다.")
    @Test
    void request_fail_invalid_password() throws Exception {
        String token = Base64.getEncoder().encodeToString((TEST_ADMIN_MEMBER.getEmail() + ":" + "invalid").getBytes());

        ResultActions response = mockMvc.perform(get("/members")
                .header("Authorization", "Basic " + token)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );

        response.andExpect(status().isUnauthorized());
    }

    @DisplayName("인증된 사용자는 자신의 정보를 조회할 수 있다.")
    @Test
    void request_success_members_me() throws Exception {
        String token = Base64.getEncoder().encodeToString((TEST_USER_MEMBER.getEmail() + ":" + TEST_USER_MEMBER.getPassword()).getBytes());

        ResultActions response = mockMvc.perform(get("/members/me")
                .header("Authorization", "Basic " + token)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE));

        response.andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("name").value(TEST_USER_MEMBER.getName()));
    }

    @DisplayName("인증되지 않은 사용자는 자신의 정보를 조회할 수 없다.")
    @Test
    void request_fail_members_me() throws Exception {
        ResultActions response = mockMvc.perform(get("/members/me")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE));

        response.andDo(print())
                .andExpect(status().isUnauthorized());
    }

}
