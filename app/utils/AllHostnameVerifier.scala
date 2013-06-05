package utils

import javax.net.ssl.{SSLSession, HostnameVerifier}

/**
 * Created with IntelliJ IDEA.
 * User: edmund
 * Date: 5/31/13
 * Time: 1:07 PM
 * To change this template use File | Settings | File Templates.
 */
class AllHostnameVerifier extends HostnameVerifier {

  def verify(hostname : String, session : SSLSession) : Boolean =  {
    return true;
  }

}
