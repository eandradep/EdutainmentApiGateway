package com.ups.hihp4c.edutainment.api.gateway

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cloud.netflix.eureka.EnableEurekaClient

@EnableEurekaClient
@SpringBootApplication
class EdutainmentApiGatewayApplication

fun main(args: Array<String>) {
    runApplication<EdutainmentApiGatewayApplication>(*args)
}
