package ru.mtuci.coursemanagement.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Фильтр для добавления дополнительных заголовков безопасности.
 * Устраняет оставшиеся уязвимости из OWASP ZAP сканирования.
 * 
 * Добавляемые заголовки:
 * - Cross-Origin-Opener-Policy (защита от Spectre)
 * - Cross-Origin-Embedder-Policy (защита от Spectre)
 * - Cross-Origin-Resource-Policy
 * - Permissions-Policy (замена устаревшего Feature-Policy)
 * - Referrer-Policy
 * - X-Content-Type-Options
 * - X-Frame-Options
 * - X-XSS-Protection
 * - Strict-Transport-Security (для HTTPS)
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CustomSecurityHeadersFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        // Cross-Origin-Opener-Policy (COOP) - защита от Spectre атак
        // Изолирует контекст просмотра для предотвращения межсайтовых атак
        response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        
        // Cross-Origin-Embedder-Policy (COEP) - защита от Spectre атак
        // Требует явного разрешения для загрузки кросс-origin ресурсов
        response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
        
        // Cross-Origin-Resource-Policy (CORP)
        // Контролирует какие сайты могут загружать ресурсы
        response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
        
        // Permissions-Policy (замена Feature-Policy)
        // Контролирует доступ к различным browser features и APIs
        response.setHeader("Permissions-Policy", 
            "geolocation=(), " +          // Отключить геолокацию
            "microphone=(), " +            // Отключить микрофон
            "camera=(), " +                // Отключить камеру
            "payment=(), " +               // Отключить Payment Request API
            "usb=(), " +                   // Отключить WebUSB API
            "magnetometer=(), " +          // Отключить магнитометр
            "gyroscope=(), " +             // Отключить гироскоп
            "accelerometer=(), " +         // Отключить акселерометр
            "interest-cohort=()");         // Отключить FLoC (Google)
        
        // Referrer-Policy
        // Контролирует передачу Referer заголовка
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        
        // X-Content-Type-Options
        // Предотвращает MIME-sniffing атаки
        response.setHeader("X-Content-Type-Options", "nosniff");
        
        // X-Frame-Options
        // Защита от clickjacking атак
        response.setHeader("X-Frame-Options", "SAMEORIGIN");
        
        // X-XSS-Protection
        // Включает встроенную защиту браузера от XSS (устаревший, но поддерживается)
        response.setHeader("X-XSS-Protection", "1; mode=block");
        
        // Strict-Transport-Security (HSTS)
        // Только для HTTPS соединений
        // Принуждает браузер использовать только HTTPS
        if (request.isSecure()) {
            response.setHeader("Strict-Transport-Security", 
                "max-age=31536000; includeSubDomains; preload");
        }
        
        // Cache-Control для чувствительных страниц
        String uri = request.getRequestURI();
        if (uri.contains("/login") || uri.contains("/register") || 
            uri.contains("/courses") || uri.contains("/students")) {
            response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Expires", "0");
        }
        
        filterChain.doFilter(request, response);
    }
    
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Не применять фильтр к статическим ресурсам для производительности
        String path = request.getRequestURI();
        return path.startsWith("/css") || 
               path.startsWith("/js") || 
               path.startsWith("/images") ||
               path.startsWith("/favicon.ico");
    }
}
