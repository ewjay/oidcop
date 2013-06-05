package utils


import javax.net.ssl.{X509TrustManager}
import java.security.cert.X509Certificate




/**
 * Created with IntelliJ IDEA.
 * User: edmund
 * Date: 5/31/13
 * Time: 12:55 PM
 * To change this template use File | Settings | File Templates.
 */
class X509TrustAllManager extends X509TrustManager {
  def getAcceptedIssuers : Array[java.security.cert.X509Certificate] = {
    null
  }

  def checkClientTrusted(certs : Array[X509Certificate], authType : String) {
  }

  def checkServerTrusted(certs : Array[X509Certificate], authType : String) {
  }

}
