package com.edutainment.api.gateway

import io.swagger.v3.oas.annotations.OpenAPIDefinition
import io.swagger.v3.oas.annotations.info.Contact
import io.swagger.v3.oas.annotations.info.Info
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cloud.netflix.eureka.EnableEurekaClient

@EnableEurekaClient
@SpringBootApplication
@OpenAPIDefinition(
    info = Info(
        title = "EDUTAINMENT API GATEWAY",
        version = "1.0",
        description = "EDUTAINMENT API GATEWAY DOCUMENTATION, THIS DOCUMENTATION CONTAINS BASIC INFORMATION" +
                "ABOUT THE MINIMAL REQUIRED SERVICES TO COMPLETE THE SUCCESSFULLY IMPLEMENTATION OF VR APPLICATION OR " +
                "GAMIFICATION APPS.",
        contact = Contact(
            name = "EDISON ANDRADE", email = "eandradep@est.ups.edu.ec"
        ),
    )
)
class EdutainmentApiGatewayApplication

fun main(args: Array<String>) {
    runApplication<EdutainmentApiGatewayApplication>(*args)
}
