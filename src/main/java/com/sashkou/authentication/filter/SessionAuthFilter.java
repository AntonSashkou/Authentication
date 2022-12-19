package com.sashkou.authentication.filter;

import com.sashkou.authentication.service.BasicAuthService;
import com.sashkou.authentication.service.SessionAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class SessionAuthFilter implements Filter {
    private static final String FILTER_PATH = "/secret/session-auth";
    private static final String BASIC_AUTH_MARKER = "Basic";
    private static final String SESSION_AUTH_MARKER = "Session";

    private final BasicAuthService basicAuthService;
    private final SessionAuthService sessionAuthService;

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
                String sessionId = sessionAuthService.createSession(authorizationHeader);
                respondWithSessionId(httpServletResponse, sessionId);
            }

            return;
        }

        if (authorizationHeader.contains(SESSION_AUTH_MARKER)) {
            boolean isSessionAuthSucceed = sessionAuthService.validateSession(authorizationHeader);
            if (!isSessionAuthSucceed) {
                unauthorized(httpServletResponse);
            } else {
                filterChain.doFilter(servletRequest, servletResponse);
            }
        }
    }

    private void respondWithSessionId(HttpServletResponse response, String sessionId) {
        response.addHeader("session-id", sessionId);
        response.setStatus(HttpStatus.OK.value());
    }

    private void unauthorized(HttpServletResponse response) {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }

    private boolean shouldFilter(HttpServletRequest request) {
        return request.getRequestURI().contains(FILTER_PATH);
    }
}
