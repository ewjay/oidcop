package com.nimbusds.jose;

import net.jcip.annotations.Immutable;
/**
 * Created with IntelliJ IDEA.
 * User: Edmund
 * Date: 4/29/13
 * Time: 5:15 PM
 * To change this template use File | Settings | File Templates.
 */
@Immutable
public class PayloadExtBytes extends Payload {
    public PayloadExtBytes(byte[] bytes) { super(bytes);}
}
