package com.accantosystems.stratoss.vnfmdriver.model;

public enum MessageDirection {
    RECEIVED,
    SENT;
    @Override
    public String toString(){
        return this.name().toLowerCase();
    }
}
