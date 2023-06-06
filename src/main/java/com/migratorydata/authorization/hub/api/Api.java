package com.migratorydata.authorization.hub.api;

public class Api {

    private Limit limit = new Limit(100, 5000, 1000);

    private final String apiId;

    public Api(String apiId) {
        this.apiId = apiId;
    }

    public Limit getLimit() {
        return limit;
    }

    public String getApiId() {
        return apiId;
    }

    @Override
    public String toString() {
        return "Api [ " + apiId + " ] {" +
                ", limit=" + limit +
                '}';
    }

    public void updateLimit(Limit limit) {
        this.limit.updateLimit(limit);
    }
}
