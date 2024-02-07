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

/**
 * JwtAuthenticationFilter is a Spring WebFilter that performs JWT token authentication.
 */
@Component
class JwtAuthenticationFilter : WebFilter {

    /**
     * This variable represents a logger factory for the JwtAuthenticationFilter class.
     * It is used to create instances of ILogger that log messages for a specified class.
     * The LoggerFactory.getLogger() method takes a Class<T> parameter to specify the class for which the logger is created.
     */
    private val loggerFactory = LoggerFactory.getLogger(JwtAuthenticationFilter::class.java)

    /**
     * The `authenticationManager` property is an instance of the `ReactiveAuthenticationManager` interface.
     * It is used for performing authentication of JWT tokens in the `JwtAuthenticationFilter` class.
     *
     * @see JwtAuthenticationFilter
     * @see ReactiveAuthenticationManager
     */
    @Autowired
    private lateinit var authenticationManager: ReactiveAuthenticationManager

    /**
     * Filters the server web exchange to handle authentication using a JWT token.
     *
     * @param exchange The server web exchange.
     * @param chain The web filter chain.
     * @return A Mono that represents the completion of the request processing.
     */
    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        loggerFactory.info(" ---------> Start request <--------- ")

        return Mono.justOrEmpty<String>(this.validateFirstPart(exchange))
            .filter { authHeader: String -> this.validateStartWith(authHeader) }
            .switchIfEmpty(this.validateSwithc(chain, exchange))
            .map { token: String ->
                loggerFactory.info("Token identify!")
                token.replace(
                    "Bearer ",
                    ""
                )
            }
            .flatMap { token: String? ->
                authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken(null, token)
                )
            }
            .flatMap { authentication ->
                loggerFactory.info(" ----------> End request <---------- ")
                chain.filter(
                    exchange
                ).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
            }
    }

    private fun validateSwithc(chain: WebFilterChain, exchange: ServerWebExchange): Mono<out String> {
        loggerFactory.info("validateSwithc");
        val x: Mono<out String> = chain.filter(exchange).then(Mono.empty());

        loggerFactory.info("validateStartWith. {}", x)
        return x;
    }


    private fun validateStartWith(authHeader: String): Boolean {
        loggerFactory.info("validateStartWith");
        val x = authHeader.startsWith("Bearer ")
        loggerFactory.info("validateStartWith. {}", x)
        return x
    }

    private fun validateFirstPart(exchange: ServerWebExchange): String? {
        loggerFactory.info("data del loggesr");
        loggerFactory.info("headers {}", exchange.request.headers);
        exchange.request.headers.forEach { entry ->
            loggerFactory.info("headers {}", entry.key)
            if (entry.key.equals("Access-Control-Request-Headers")) {
                entry.value.forEach { s: String? ->
                    loggerFactory.info("Access-Control-Request-Headers {}", s)
                }
            }
        }
        ;
        val x = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
        loggerFactory.info("data del loggesr. {}", x)
        return x
    }
}