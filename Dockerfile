FROM gradle:7.6.1-jdk8 AS build-extension
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle build shadowJar

FROM migratorydata/server:6.0-test
WORKDIR /migratorydata
COPY --from=build-extension /home/gradle/src/build/libs/authorization.jar ./addons/authorization-hub/authorization.jar
CMD ["./start-migratorydata.sh"]