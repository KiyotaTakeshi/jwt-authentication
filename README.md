## Setup

```shell
# set up Java 17(you also can use 11 for this app)
export JAVA_HOME=`/usr/libexec/java_home -v 17`

$ java -version                                                
openjdk version "17" 2021-09-14 LTS
OpenJDK Runtime Environment Corretto-17.0.0.35.2 (build 17+35-LTS)
OpenJDK 64-Bit Server VM Corretto-17.0.0.35.2 (build 17+35-LTS, mixed mode, sharing)

# run MySQL container
docker compose up -d
```

## Run with `develop` profile 

use environment variables

```shell
export SPRING_PROFILES_ACTIVE=develop

ARTIFACT_ID=$(./mvnw org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate -Dexpression=project.artifactId -q -DforceStdout)
ARTIFACT_VERSION=$(./mvnw org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate -Dexpression=project.version -q -DforceStdout)

# you also can use following command if you create single artifact
# java -jar $(\ls target/*jar)
java -jar target/$ARTIFACT_ID-$ARTIFACT_VERSION.jar

# or use maven wrapper
#./mvnw spring-boot:run
```

use active profiles 

```shell
unset SPRING_PROFILES_ACTIVE

java -jar -Dspring.profiles.active=develop target/$ARTIFACT_ID-$ARTIFACT_VERSION.jar
```

```shell
unset SPRING_PROFILES_ACTIVE

./mvnw spring-boot:run -Dspring-boot.run.profiles=development
```

## Test

you can you [postman collection](./postman)

```shell
$ curl --dump-header - --location --request POST 'http://localhost:8080/login' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'userName=mike' \
--data-urlencode 'password=passw0rd' -s | grep -E 'HTTP|access_token|refresh_token'

HTTP/1.1 200 
access_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtaWtlIiwicm9sZXMiOlsiUk9MRV9VU0VSIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9sb2dpbiIsImV4cCI6MTYzMzMwNTIzM30.YSZFKbMQNK9tjwE_8-LrTM7XFBYN-Tl7LCeB27OxNG8
refresh_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtaWtlIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2xvZ2luIiwiZXhwIjoxNjMzMzA1MjMzfQ.2KZMKQjV5Krp6LR2oscmu5SSlxcSON46Us0fjv7RZW8
```

[decode access_token](https://jwt.io/#debugger-io?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtaWtlIiwicm9sZXMiOlsiUk9MRV9VU0VSIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9sb2dpbiIsImV4cCI6MTYzMzMwNTMzMn0.7CsltATcvga1H1VY_kEAzvxjbYW8i04fQAZ6mDnk9S0)
