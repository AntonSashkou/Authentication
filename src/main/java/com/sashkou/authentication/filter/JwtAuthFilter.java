package com.sashkou.authentication.filter;

import com.sashkou.authentication.service.BasicAuthService;
import com.sashkou.authentication.service.JwtAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
@WebFilter(urlPatterns = "/secret/jwt-auth")
public class JwtAuthFilter implements Filter {
    private static final String FILTER_PATH = "/secret/jwt-auth";
    private static final String BASIC_AUTH_MARKER = "Basic";
    private static final String JWT_AUTH_MARKER = "Bearer";

    private final BasicAuthService basicAuthService;
    private final JwtAuthService jwtAuthService;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        if (!shouldFilter((HttpServletRequest) servletRequest)) {
            filterChain.doFilter(servletRequest, servletResponse);
        }

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        String authorizationHeader = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader.contains(BASIC_AUTH_MARKER)) {
            boolean isBasicAuthSucceed = basicAuthService.auth(authorizationHeader);
            if (!isBasicAuthSucceed) {
                unauthorized(httpServletResponse);
            } else {
                String sessionId = jwtAuthService.createToken(authorizationHeader);
                respondWithJwt(httpServletResponse, sessionId);
            }

            return;
        }

        if (authorizationHeader.contains(JWT_AUTH_MARKER)) {
            boolean isJwtValid = jwtAuthService.validateToken(authorizationHeader);
            if (!isJwtValid) {
                unauthorized(httpServletResponse);
            } else {
                filterChain.doFilter(servletRequest, servletResponse);
            }
        }

    }

    private void unauthorized(HttpServletResponse response) {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }

    private void respondWithJwt(HttpServletResponse response, String jwt) {
        response.addHeader("jwt", jwt);
        response.setStatus(HttpStatus.OK.value());
    }

    private boolean shouldFilter(HttpServletRequest request) {
        return request.getRequestURI().contains(FILTER_PATH);
    }
}
