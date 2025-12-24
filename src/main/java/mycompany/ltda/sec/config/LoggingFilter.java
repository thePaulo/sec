package mycompany.ltda.sec.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class LoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        System.out.println("=== Request Log ===");
        System.out.println("Method: " + request.getMethod());
        System.out.println("URL: " + request.getRequestURL());
        System.out.println("Path: " + request.getServletPath());
        System.out.println("Headers:");
        request.getHeaderNames().asIterator().forEachRemaining(header -> {
            System.out.println("  " + header + ": " + request.getHeader(header));
        });
        System.out.println("===================");

        filterChain.doFilter(request, response);

        System.out.println("=== Response Log ===");
        System.out.println("Status: " + response.getStatus());
        System.out.println("====================");
    }
}