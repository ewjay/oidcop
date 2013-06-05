package com.nimbusds.jose;

import net.jcip.annotations.Immutable;

/**
 * Created with IntelliJ IDEA.
 * User: Edmund
 * Date: 4/29/13
 * Time: 5:18 PM
 * To change this template use File | Settings | File Templates.
 */
@Immutable
public class PayloadExtBase64Url extends Payload {
    public PayloadExtBase64Url(com.nimbusds.jose.util.Base64URL base64URL) {super(base64URL);}
}
