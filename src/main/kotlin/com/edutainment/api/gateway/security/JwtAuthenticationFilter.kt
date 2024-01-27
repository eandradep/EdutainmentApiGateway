package com.edutainment.api.gateway.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

import org.slf4j.LoggerFactory

@Component
class JwtAuthenticationFilter : WebFilter {

    private val loggerFactory = LoggerFactory.getLogger(JwtAuthenticationFilter::class.java)

    @Autowired
    private lateinit var authenticationManager: ReactiveAuthenticationManager

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        return Mono.justOrEmpty<String>(exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION))
            .filter { authHeader: String -> authHeader.startsWith("Bearer ") }
            .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
            .map { token: String ->
                loggerFactory.info("Token identificado: {}", token)
                token.replace(
                    "Bearer ",
                    ""
                )
            }
            .flatMap { token: String? ->
                loggerFactory.info("New token: {}", token)
                authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken(null, token)
                )
            }
            .flatMap { authentication ->
                loggerFactory.info("autentication !!!: {}", authentication)
                chain.filter(
                    exchange
                ).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
            }
    }
}