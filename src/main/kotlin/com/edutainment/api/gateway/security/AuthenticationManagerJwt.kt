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


@Component
class AuthenticationManagerJwt : ReactiveAuthenticationManager {

    private val loggerFactory = LoggerFactory.getLogger(JwtAuthenticationFilter::class.java)

    @Value("\${config.security.oauth.jwt.key}")
    private lateinit var llaveJwt: String

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