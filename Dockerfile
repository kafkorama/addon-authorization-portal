FROM gradle:7.6.1-jdk8 AS build-extension
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle build shadowJar

FROM kafkorama/gateway:6.0.22
WORKDIR /kafkorama-gateway
COPY --from=build-extension /home/gradle/src/build/libs/authorization.jar ./addons/authorization-portal/authorization.jar
CMD ["./start-kafkorama-gateway.sh"]
