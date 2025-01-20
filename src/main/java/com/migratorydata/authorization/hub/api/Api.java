package com.migratorydata.authorization.hub.api;

public class Api {

    private final String apiId;

    public Api(String apiId) {
        this.apiId = apiId;
    }

    public String getApiId() {
        return apiId;
    }

    @Override
    public String toString() {
        return "Api [ " + apiId + " ]";
    }
}
