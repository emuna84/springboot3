package me.sg.config;


import lombok.RequiredArgsConstructor;
import me.sg.service.UserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {


    private final UserDetailService userService;

    /*스프링 시큐리티 기능 비활성화
     인증, 인가 서비스를 모든 곳에 적용하지 않음
     static 하위 경로에 있는 리소스와 h2의 데이터를 확인하는 사용하는 h2-console 하위 url 대상으로 ignoring() 메소드를 사용
     */
    @Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring()
                .requestMatchers(toH2Console())
                .requestMatchers(new AntPathRequestMatcher("/static/**"));
    }

/*
    특정 HTTP 요청에 대한 웹 기반 보안 구성
    인증,인가, 로그인, 로그아웃 관련 설정
 */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests(auth -> auth // 인증,인가 설정/ 특정경로에 대한 액세스 설정
                        .requestMatchers( // 특정 요청과 일치하는 url에 대한 액세스를 설정
                                new AntPathRequestMatcher("/login"),
                                new AntPathRequestMatcher("/signup"),
                                new AntPathRequestMatcher("/user")
                        ).permitAll()   // 누구나 접근이 가능하게 설정 /login,signup,user 요청이 오면 인증/인가 없이도 접근
                        .anyRequest().authenticated())
                .formLogin(formLogin -> formLogin // 폼기반 로그인 설정
                        .loginPage("/login")            //  로그인 페이지 경로 설정
                        .defaultSuccessUrl("/articles") //  로그인이 완려되었을때 이동할 경로 설정
                )
                .logout(logout -> logout            //로그아웃설정
                        .logoutSuccessUrl("/login")     //  로그아웃이 완료되었을때 이동할 경로 설정
                        .invalidateHttpSession(true)    //  로그아웃 이후에 세션을 전체 삭제할지 여부 설정
                )
                .csrf(AbstractHttpConfigurer::disable)  // CSRF 설정 비활성화
                .build();
    }
    /*
        인증관리자 관련 설정 ddddd
        사용자 정보를 가져올 서비스를 재정의하거나, 인증방법(LDAP, JDBC) 등을 설정
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, BCryptPasswordEncoder bCryptPasswordEncoder, UserDetailService userDetailService) throws Exception {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userService);    //  사용자 정보를 가져올 서비스를 설정, 이때 설정하는 서비스 클래스는 반드시 UserDetailsService를 상속
        authProvider.setPasswordEncoder(bCryptPasswordEncoder); //  비밀번호를 암호화 하기 위한 인코더 설정
        return new ProviderManager(authProvider);
    }
/*
    패스워드 인커더로 사용할 빈 등록
 */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}