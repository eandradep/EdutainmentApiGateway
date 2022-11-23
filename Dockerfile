FROM openjdk:11
ENV JAVA_OPTS=""
ARG JAR_FILE
ADD ${JAR_FILE} api-gateway-server.jar
 # use a volume is mor efficient and speed that filesystem
VOLUME /tmp
ENV TZ America/Lima
ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar /api-gateway-server.jar"]

