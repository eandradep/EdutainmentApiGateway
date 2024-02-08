package com.edutainment.api.gateway.security

import org.slf4j.LoggerFactory
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

@Component
class JwtAuthenticationFilter : WebFilter {
    private val logger = LoggerFactory.getLogger(JwtAuthenticationFilter::class.java)

    @Autowired
    private lateinit var authenticationManager: ReactiveAuthenticationManager

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        logger.info(" ---------> Start request <--------- ")
        return Mono.justOrEmpty(this.validateFirstPart(exchange))
            .filter(this::validateStartWith)
            .switchIfEmpty(this.validateSwitch(chain, exchange))
            .map { token -> token.replace("Bearer ", "")}
            .flatMap { token: String ->
                authenticationManager.authenticate(UsernamePasswordAuthenticationToken(null, token))
            }
            .flatMap { authentication ->
                logger.info(" ----------> End request <---------- ")
                chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
            }
    }

    private fun validateSwitch(chain: WebFilterChain, exchange: ServerWebExchange): Mono<String> {
        return chain.filter(exchange).then(Mono.empty())
    }

    private fun validateStartWith(authHeader: String): Boolean = authHeader.startsWith("Bearer ")

    private fun validateFirstPart(exchange: ServerWebExchange): String? {
        val authHeader = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
        logger.info("Authorization token: {}", authHeader)
        return authHeader
    }
}