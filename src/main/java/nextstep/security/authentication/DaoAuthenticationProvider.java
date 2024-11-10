package nextstep.security.authentication;

import nextstep.security.userdetails.UserDetails;
import nextstep.security.userdetails.UserDetailsService;

import java.util.Objects;

public class DaoAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;

    public DaoAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UserDetails userDetails = userDetailsService.loadUserByUsername(authentication.getPrincipal().toString());
        if (!Objects.equals(userDetails.getPassword(), authentication.getCredentials())) {
            throw new AuthenticationException();
        }
        return UsernamePasswordAuthenticationToken.authenticated(userDetails.getUsername(), userDetails.getPassword(), userDetails.getRoles());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
