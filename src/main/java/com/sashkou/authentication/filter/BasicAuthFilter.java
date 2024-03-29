package com.sashkou.authentication.filter;

import com.sashkou.authentication.service.BasicAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class BasicAuthFilter implements Filter {
    private static final String FILTER_PATH = "/secret/basic-auth";

    private final BasicAuthService basicAuthService;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        if (!shouldFilter((HttpServletRequest) servletRequest)) {
            filterChain.doFilter(servletRequest, servletResponse);
        }

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        String authorizationHeader = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);

        if (!StringUtils.hasText(authorizationHeader)) {
            unauthorized(httpServletResponse);
            return;
        }

        boolean authenticated = basicAuthService.auth(authorizationHeader);
        if (!authenticated) {
            unauthorized(httpServletResponse);
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    private void unauthorized(HttpServletResponse response) {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }

    private boolean shouldFilter(HttpServletRequest request) {
        return request.getRequestURI().contains(FILTER_PATH);
    }
}
