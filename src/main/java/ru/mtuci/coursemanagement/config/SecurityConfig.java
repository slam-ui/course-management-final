package ru.mtuci.coursemanagement.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.CrossOriginEmbedderPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter;
import org.springframework.security.web.header.writers.PermissionsPolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/register", "/error", "/css/**", "/js/**", "/images/**").permitAll()
                .requestMatchers("/h2-console/**").denyAll()
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/actuator/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/", true)
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .permitAll()
            )
            .csrf(Customizer.withDefaults()) // Стандартная настройка CSRF
            .headers(headers -> headers
                // 1. Строгая CSP (УБРАЛИ 'unsafe-inline')
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; " +
                                    "script-src 'self'; " + // Только локальные скрипты
                                    "style-src 'self'; " +  // Только локальные стили
                                    "img-src 'self' data:; " +
                                    "font-src 'self'; " +
                                    "connect-src 'self'; " +
                                    "frame-ancestors 'self'; " +
                                    "base-uri 'self'; " +
                                    "form-action 'self'")
                )
                // 2. Защита от Clickjacking
                .frameOptions(frame -> frame.sameOrigin())
                // 3. Защита от MIME-sniffing
                .contentTypeOptions(contentType -> {})
                // 4. Защита XSS
                .xssProtection(xss -> xss
                    .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
                )
                // 5. Referrer Policy
                .referrerPolicy(referrer -> referrer
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                )
                // 6. Permissions Policy (убирает предупреждение "Заголовок политики разрешений...")
                .addHeaderWriter(new PermissionsPolicyHeaderWriter(
                    "geolocation=(), camera=(), microphone=(), usb=()"))
                
                // 7. Изоляция сайта (убирает предупреждения Spectre и Sec-Fetch)
                .crossOriginOpenerPolicy(coop -> coop
                    .policy(CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN))
                .crossOriginEmbedderPolicy(coep -> coep
                    .policy(CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP))
                .crossOriginResourcePolicy(corp -> corp
                    .policy(CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy.SAME_ORIGIN))
            )
            .sessionManagement(session -> session
                .sessionFixation().migrateSession()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
