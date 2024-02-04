package com.edutainment.api.gateway.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono
import java.util.*
import java.util.stream.Collectors
import javax.crypto.SecretKey


/**
 * AuthenticationManagerJwt is a class that implements ReactiveAuthenticationManager interface for JWT token authentication.
 * It authenticates the given authentication object by validating the JWT token.
 * @see ReactiveAuthenticationManager
 *
 * @property loggerFactory The logger factory for the JwtAuthenticationFilter class.
 * @property llaveJwt The key used for JWT token verification in the application.
 */
@Component
class AuthenticationManagerJwt : ReactiveAuthenticationManager {

    /**
     * This variable represents a logger factory for the JwtAuthenticationFilter class.
     * It is used to create instances of ILogger that log messages for a specified class.
     * The LoggerFactory.getLogger() method takes a Class<T> parameter to specify the class for which the logger is created.
     */
    private val loggerFactory = LoggerFactory.getLogger(JwtAuthenticationFilter::class.java)

    /**
     * The llaveJwt variable represents the key used for JWT token verification in the application.
     * It is loaded from the configuration file using the @Value annotation.
     */
    @Value("\${config.security.oauth.jwt.key}")
    private lateinit var llaveJwt: String

    /**
     * Authenticates the given authentication object by validating the JWT token.
     *
     * @param authentication The authentication object to be authenticated.
     * @return A Mono that emits the authenticated Authentication object.
     */
    override fun authenticate(authentication: Authentication): Mono<Authentication> {
        return Mono.just(authentication.credentials.toString())
            .map { token ->
                val llave: SecretKey = Keys.hmacShaKeyFor(Base64.getEncoder().encode(llaveJwt.toByteArray()))
                Jwts.parserBuilder().setSigningKey(llave).build().parseClaimsJws(token).body
            }
            .map { claims ->
                loggerFactory.info("Authorities found.")
                val username = claims["user_name"] as String
                val roles = claims["authorities"] as List<*>
                val authorities: Collection<GrantedAuthority> =
                    roles.stream().map { role -> SimpleGrantedAuthority(role.toString()) }.collect(Collectors.toList())
                loggerFactory.info("User to request, {} and role size {}", username, authorities.size)
                UsernamePasswordAuthenticationToken(username, null, authorities)
            }
    }
}