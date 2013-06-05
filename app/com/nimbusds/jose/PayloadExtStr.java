package com.nimbusds.jose;

import net.jcip.annotations.Immutable;
/**
 * Created with IntelliJ IDEA.
 * User: Edmund
 * Date: 4/29/13
 * Time: 5:14 PM
 * To change this template use File | Settings | File Templates.
 */
@Immutable
public class PayloadExtStr extends Payload{
    public PayloadExtStr(String string) { super(string);}
}
