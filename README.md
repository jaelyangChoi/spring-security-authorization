# spring-security-authorization

---
``Spring Security`` 의 내부 구조를 분석하여 인가 기능을 직접 구현한다.


1. 인가(권한 부여) 기능 구현
   1. 사용자 권한 추가 및 검증
   2. 메서드 애너테이션을 이용하여 접근 제어 기능을 적용 (feat.AOP)


2. 권한 검증 로직을 AuthorizationFilter 로 리팩터링


3. Role Hierarchy(권한의 계층 구조) 구현


4. 스프링 시큐리티 구조 적용
   1. AuthorizationManager를 활용하여 인가 과정 추상화
   2. 요청별 권한 검증 정보를 별도의 객체로 분리하여 관리
   3. RoleHierarchy 리팩터링
   4. AuthoritiesAuthorizationManager에서의 RoleHierarchy 활용
