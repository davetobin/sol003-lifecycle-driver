package com.accantosystems.stratoss.vnfmdriver.model;

public enum MessageType {
    REQUEST,
    RESPONSE,
    MESSAGE;

    @Override
    public String toString() {
        return this.name().toLowerCase();
    }
}