package com.spring.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JWTAuthenicationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    /**
     *
     * @param request(our request what we are sending)
     * @param response(the response what we are getting)
     * @param filterChain(it contains multiple chain filters)
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal
    (@NonNull HttpServletRequest request,
     @NonNull HttpServletResponse response,
     @NonNull FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith(("Bearer"))){
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUserName("");

    }
}
