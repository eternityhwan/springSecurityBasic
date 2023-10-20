package com.eternity.basicsecurity.configuration;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Configuration // 설정 클래스니까 붙여주는 어노테이션
@EnableWebSecurity // 웹시큐리티 활성화
public class SecurityConfig {
    // 사용자 정의 보안 설정 클래스
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests() // 인가정책 설정
                .anyRequest().authenticated();
        http
                .formLogin() // formlogin 인증 정책 설정
//                .loginPage("/loginPage")  // 사용자 정의 로그인 페이지 지정
                .defaultSuccessUrl("/") // 로그인 성공 이동 페이지
                .failureUrl("/login") // 로그인 실패 후 이동 페이지
                .usernameParameter("userId") // 아이디 파라메터 설정
                .passwordParameter("passwd") // 패스워드 파라미터 설정
                .loginProcessingUrl("/login_proc")// 로그인 form action url
                .successHandler(new AuthenticationSuccessHandler() { // 로그인이 성공했을 때 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication" + authentication.getName());
                        response.sendRedirect("/"); // 로그인 성공하면 루트페이지로 보내버린다.
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception" + exception.getMessage());
                        response.sendRedirect("/login"); // 실패하면 로그인페이지로 보내버린다.
                    }
                })
                .permitAll() /// 위 인증경로로 접근하는 사용자는 모두 허용한다는 뜻

        ;
        http
                .logout() // 로그아웃 기능이 작동한다
                .logoutUrl("/logout")  // 로그아웃 처리 url, post 방식으로 해야해
                .logoutSuccessUrl("/login") // 로그 아웃 성공 후 이동 url
                .deleteCookies("JSESSIONID", "remember-me") // 로그아웃 후 쿠키 삭제
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate(); // 로그아웃 핸들러, 로그 아웃이후 뭔가 했으면 좋겟다하면 해라
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                }) // 로그아웃 성공 후 핸들러 사용하면 더 다양한 로직 구현가능
                .deleteCookies("remember-me") // remember-me 이름으로 쿠키를 발행한다. 쿠키 이름을 적어주면 된다는 것이지
                ;

        http
                .rememberMe() // rememberMe 기능이 작동한다
                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600) // default는 14일
                .alwaysRemember(true); // 리멈버 미 기능이 활성화되지 않아도 항상 실행
//                .userDetailsService()
    return http.build();
    }
}
