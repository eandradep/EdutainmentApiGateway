package com.edutainment.api.gateway.filters
import java.util.Optional

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.ResponseCookie
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange

import reactor.core.publisher.Mono

@Component
class ApiGatewayFilter(configClass: Class<Configuracion>?) :
    AbstractGatewayFilterFactory<ApiGatewayFilter.Configuracion>(configClass) {

    private val logger: Logger = LoggerFactory.getLogger(ApiGatewayFilter::class.java)


    override fun apply(config: Configuracion): GatewayFilter {
        return GatewayFilter { exchange: ServerWebExchange, chain: GatewayFilterChain ->
            logger.info("ejecutando pre gateway filter factory: " + config.mensaje)
            chain.filter(exchange)
                .then(Mono.fromRunnable {
                    Optional.ofNullable(config.cookieValor).ifPresent { cookie ->
                        exchange.response.addCookie(ResponseCookie.from(config.cookieNombre!!, cookie).build())
                    }
                    logger.info("ejecutando post gateway filter factory: " + config.mensaje)
                })
        }
    }


    override fun name(): String {
        return "EjemploCookie"
    }

    override fun shortcutFieldOrder(): List<String> {
        return listOf("mensaje", "cookieNombre", "cookieValor")
    }

    class Configuracion {
        var mensaje: String? = null
        var cookieValor: String? = null
        var cookieNombre: String? = null
    }
}