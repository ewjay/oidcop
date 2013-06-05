package com.nimbusds.jose;

import net.jcip.annotations.Immutable;
/**
 * Created with IntelliJ IDEA.
 * User: Edmund
 * Date: 4/29/13
 * Time: 5:16 PM
 * To change this template use File | Settings | File Templates.
 */
@Immutable
public class PayloadExtJson extends  Payload{
    public PayloadExtJson(net.minidev.json.JSONObject json) { super(json);}
}
