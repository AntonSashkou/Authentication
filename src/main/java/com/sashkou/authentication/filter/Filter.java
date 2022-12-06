package com.sashkou.authentication.filter;

import com.sashkou.authentication.service.Service;
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
public class Filter implements javax.servlet.Filter {

    private final Service service;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        String authorizationHeader = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);

        if (!StringUtils.hasText(authorizationHeader)) {
            unauthorized(httpServletResponse);
            return;
        }

        boolean authenticated = service.handleAuth(authorizationHeader);
        if (!authenticated) {
            unauthorized(httpServletResponse);
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    private void unauthorized(HttpServletResponse response) {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }
}
