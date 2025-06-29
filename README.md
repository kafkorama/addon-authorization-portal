# Authorization PORTAL add-on

This Kafkorama gateway add-on allows you to authorize users to subscribe to and/or publish real-time messages on specific
subjects using the JSON Web Tokens (JWT) standard.

The add-on is used with Kafkorama portal, which is a web application that allows users to manage their subscriptions and publish messages
to subjects in a Kafkorama gateway. The add-on provides the necessary authorization checks to ensure that users can only access the subjects they are authorized for.

### Overview

Please refer to the following <a target="_blank" href="https://migratorydata.com/blog/migratorydata-jwt-auth/">blog post</a> for an overview of the JWT authorization add-on.

### Enabling the add-on

This add-on is preinstalled in the MigratoryData server under the following folder,
according to the package type used to install the MigratoryData server:

| Location                                            | Package type                         |
|-----------------------------------------------------|--------------------------------------|
| `addons/authorization-portal`                          | Platform-independent tarball package |
| `/usr/share/kafkorama-gateway/addons/authorization-portal` | `RPM` or `DEB` Linux package         |

Its default configuration is available under the following folder:

| Location                                      | Package type                         |
|-----------------------------------------------|--------------------------------------|
| `addons/authorization-portal`                    | Platform-independent tarball package |
| `/etc/kafkorama-gateway/addons/authorization-portal` | `RPM` or `DEB` Linux package         |

The add-on is automatically enabled the parameter 
[Entitlement](http://kafkorama.com/docs/configuration/core-parameters/#entitlement) of the Kafkorama gateway is set on `PORTAL`.

> Entitlement = PORTAL

### Modifying the add-on

You can modify the source code of this add-on to fit your needs. The add-on is build with MigratoryData's <a target="_blank" href="https://mvnrepository.com/artifact/com.migratorydata/server-extensions-api">Server Extensions API</a>.

#### Getting the code and building

You can use the following commands to get and build the add-on:

```bash
$ git clone https://github.com/kafkorama/addon-authorization-portal.git
$ cd addon-authorization-portal
$ ./gradlew clean build shadowJar
```

#### Deploying the modified add-on

1. Copy the modified add-on from `addon-authorization-portal/build/libs/authorization.jar` to the following location of your Kafkorama gateway installation:

| Location                          | Package type                         |
|-----------------------------------|--------------------------------------|
| `extensions/`                     | Platform-independent tarball package |
| `/usr/share/kafkorama-gateway/extensions/`  | `RPM` or `DEB` Linux package         |

> **Note &mdash;**
> It is not necessary to delete the PORTAL authorization add-on `authorization.jar` made available under the folder `addons`. Loading a custom authorization extension
> `authorization.jar` from the folder `extensions` takes precedence over loading an off-the-shelf authorization extension `authorization.jar` made available under
> the folder `addons`. Note also that the name of the extension `authorization.jar` is fixed, it cannot be changed in order to be loaded by the MigratoryData server.

2. Set the parameter [Entitlement](http://kafkorama.com/docs/configuration/core-parameters/#entitlement) of the Kafkorama gateway on `Custom` (rather than on `PORTAL`)

> Entitlement = Custom

3. Finally, restart your MigratoryData server in order to reload the authorization add-on.


