package com.ctrip.infosec.rule.convert.persist;

/**
 * Created by yxjiang on 2015/6/23.
 */
public class DbExecuteException extends Exception {
    public DbExecuteException(){
        super();
    }

    public DbExecuteException(String msg){
        super(msg);
    }

    public DbExecuteException(String msg, Throwable cause){
        super(msg, cause);
    }
}
