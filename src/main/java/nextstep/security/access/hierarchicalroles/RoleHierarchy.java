package nextstep.security.access.hierarchicalroles;

import java.util.*;

public class RoleHierarchy {
    private final String defaultAuthority = "authenticated"; //기본 부여된 최하위 권한
    private Map<String, Set<String>> hierarchy = new HashMap<>();

    public RoleHierarchy(String roleStr) {
        List<String> roleList = new ArrayList<>(List.of(defaultAuthority));

        for (String role : roleStr.trim().split("<")) {
            role = role.trim();
            roleList.add(role);
            hierarchy.put(role, new HashSet<>(roleList));
        }
    }

    public Set<String> getReachableGrantedAuthorities(Set<String> authorities) {
        for (String authority : authorities) {
            if (hierarchy.containsKey(authority)) {
                return hierarchy.get(authority);
            }
        }
        return authorities;
    }
}
