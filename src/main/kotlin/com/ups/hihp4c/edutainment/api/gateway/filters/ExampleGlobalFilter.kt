package com.ups.hihp4c.edutainment.api.gateway.filters

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono


@Component
class ExampleGlobalFilter : GlobalFilter {

    private var logger: Logger = LoggerFactory.getLogger(ExampleGlobalFilter::class.java)

    override fun filter(exchange: ServerWebExchange?, chain: GatewayFilterChain?): Mono<Void> {
        logger.info("EXECUTE PRE FILTER !!!")
        return chain!!.filter(exchange).then(Mono.fromRunnable(Runnable {
            logger.info("EXECUTE POST FILTER !!!")
        }))
    }

}