package com.sashkou.authentication.filter;

import com.sashkou.authentication.service.Service;
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

    private static final String BASIC_AUTH_MARKER = "Basic";
    private static final String SESSION_AUTH_MARKER = "Session";

    private final Service service;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        String authorizationHeader = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader.contains(BASIC_AUTH_MARKER)) {
            boolean isBasicAuthSucceed = service.doBasicAuth(authorizationHeader);
            if (!isBasicAuthSucceed) {
                unauthorized(httpServletResponse);
            } else {
                String sessionId = service.createSession(authorizationHeader);
                respondWithSessionId(httpServletResponse, sessionId);
            }

            return;
        }

        if (authorizationHeader.contains(SESSION_AUTH_MARKER)) {
            boolean isSessionAuthSucceed = service.validateSession(authorizationHeader);
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

}
