package controllers

import play.api._
import play.api.mvc._
import play.api.libs.json._
import play.api.mvc.Results._
import anorm._
import play.api.db._
import play.api.Play.current
import play.api.data.Forms._
import play.api.data._
import play.api.cache.Cache
import models._

import com.nimbusds.jose
import com.nimbusds.jose._
import com.nimbusds.jose.crypto._
import com.nimbusds.jose.jwk._
import com.nimbusds.jose.util._
import com.nimbusds.jwt._

import java.io._
import java.nio.file.{Files, Paths}
import java.nio.charset.Charset
import java.nio.ByteBuffer
import java.security._
import java.security.spec.{X509EncodedKeySpec, PKCS8EncodedKeySpec, RSAMultiPrimePrivateCrtKeySpec}
import java.security.interfaces.{RSAMultiPrimePrivateCrtKey, RSAPrivateCrtKey, RSAPrivateKey, RSAPublicKey}
import java.security.cert.CertificateFactory
import java.util
import java.util.zip.{Deflater, Inflater}
import java.net.{URL, URI, URLEncoder}
import java.sql.Timestamp

import javax.net.ssl.{HostnameVerifier, HttpsURLConnection, SSLContext, SSLSession, TrustManager, X509TrustManager}
import javax.crypto.{Cipher}
import javax.crypto.spec.{SecretKeySpec, IvParameterSpec}

import org.apache.commons.io.{FileUtils, IOUtils}
import org.apache.commons.codec.binary.Hex
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.lang3.RandomStringUtils
import org.apache.http.client.utils._

import org.joda.time.DateTime
import org.joda.time.format.{DateTimeFormatter, DateTimeFormat}

import jp.t2v.lab.play2.auth._
import jp.t2v.lab.play2.stackc.{RequestWithAttributes, RequestAttributeKey, StackableController}

import utils._

//import scala.sys.process.ProcessBuilder.URLBuilder
//import scala.sys.process
//import javax.mail.AuthenticationFailedException

//import scala.Some
//import scala.collection.mutable

//import controllers.BearerException
//import controllers.OidcException


/**
 * Created with IntelliJ IDEA.
 * User: Edmund
 * Date: 4/23/13
 * Time: 2:53 PM
 * To change this template use File | Settings | File Templates.
 */

case class OidcException(error : String, desc : String = "", error_uri : String = ""  ) extends Throwable {
}

case class BearerException(error : String, desc : String = "", error_uri : String = ""  ) extends Throwable {
}

object OpenidConnect extends Controller with OptionalAuthElement with AuthConfigImpl{

  def index = Action {
    Ok(views.html.index("Your new application is ready."))
  }

  def openidConfig = Action { implicit request =>
/*    val json = JsObject(Seq(
                              "key1" -> JsString("val1"),
                              "key1" -> JsString("val2"),
                              "y2"   -> JsArray(Seq(JsNumber(1), JsString("test"))),
                              "obj"  -> JsObject(Seq("objk1" -> JsString("objval1")))
    ))*/

    val issuerPath : String = "https://" + request.host + "/oidcop"
    val json : JsObject = Json.obj(
                                      "version" -> "3.0",
                                      "issuer" -> getConfig("op.issuer"),
                                      "authorization_endpoint" -> (issuerPath + "/auth"),
      "token_endpoint" -> (issuerPath + "/token"),
      "userinfo_endpoint" -> (issuerPath + "/userinfo"),
      "check_session_iframe" -> (issuerPath + "/checksession"),
      "end_session_endpoint" -> (issuerPath + "/endsession"),
      "jwks_uri" -> ("https://" + request.host + "/assets/keys/op.jwk"),
      "registration_endpoint" -> (issuerPath + "/register"),
      "scopes_supported" -> Json.arr("openid", "profile", "email", "address", "phone", "offline_access"),
      "response_types_supported" -> Json.arr( "code",
                                              "token",
                                              "id_token",
                                              "code token",
                                              "code id_token",
                                              "id_token token",
                                              "code id_token token"
                                            ),
      "grant_types_supported" -> Json.arr("authorization_code", "implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
      "acr_values_supported" -> Json.arr(),
      "subject_types_supported" -> Json.arr("pairwise", "public"),
      "userinfo_signing_alg_values_supported" -> Json.arr("HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "none"),
      "userinfo_encryption_alg_values_supported" -> Json.arr("RSA1_5", "RSA-OAEP"),
      "userinfo_encryption_enc_values_supported" -> Json.arr("A128CBC-HS256", "A256CBC-HS512", "A128GCM", "A256GCM"),
      "id_token_signing_alg_values_supported" -> Json.arr("HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "none"),
      "id_token_encryption_alg_values_supported" -> Json.arr("RSA1_5", "RSA-OAEP"),
      "id_token_encryption_enc_values_supported" -> Json.arr("A128CBC-HS256", "A256CBC-HS512", "A128GCM", "A256GCM"),
      "request_object_signing_alg_values_supported" -> Json.arr("HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "none"),
      "request_object_encryption_alg_values_supported" -> Json.arr("RSA1_5", "RSA-OAEP"),
      "request_object_encryption_enc_values_supported" -> Json.arr("A128CBC-HS256", "A256CBC-HS512", "A128GCM", "A256GCM"),
      "token_endpoint_auth_methods_supported" -> Json.arr("client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt"),
      "token_endpoint_auth_signing_alg_values_supported" -> Json.arr("HS256", "HS384", "HS512", "RS256", "RS384", "RS512"),
      "display_values_supported" -> Json.arr("page"),
      "claim_types_supported" -> Json.arr("normal", "aggregated", "distributed"),
      "claims_supported" -> Json.arr(
                                      "sub",
                                      "name",
                                      "given_name",
                                      "family_name",
                                      "middle_name",
                                      "nickname",
                                      "preferred_username",
                                      "profile",
                                      "picture",
                                      "website",
                                      "email",
                                      "email_verified",
                                      "gender",
                                      "birthdate",
                                      "zoneinfo",
                                      "locale",
                                      "phone_number",
                                      "phone_number_verified",
                                      "address",
                                      "updated_at"
                                    ),
      "service_documentation" -> (issuerPath + "/service_doc"),
      "claims_locales_supported" -> Json.arr(),
      "ui_locales_supported" -> Json.arr(),
      "claims_parameter_supported" -> true,
      "request_parameter_supported" -> true,
      "request_uri_parameter_supported" -> true,
      "require_request_uri_registration" -> false,
      "op_policy_uri" -> (issuerPath + "/op_policy") ,
      "op_tos_uri" -> (issuerPath + "/op_tos")
    )

    Ok(Json.prettyPrint(json)).as(JSON)
  }

  def webFinger1 = TODO

  def webFinger = Action { implicit request =>
    var json = Json.obj()
    try {
      val rel : String = request.getQueryString("rel").get
      val res : String = request.getQueryString("resource").get
      if("http://openid.net/specs/connect/1.0/issuer" == rel) {
        json = Json.obj("subject" -> res,
          "links" -> Json.arr(
            Json.obj("rel" -> rel, "href" -> ("https://" + request.host))
          )
        )
      }
    }
    catch{
      case e : NoSuchElementException => {}
    }

    Ok(Json.prettyPrint(json)).as(JSON)
 }

  def register = Action(parse.json) { implicit request =>
    try {
      var result : String = ""
      val clientId = RandomStringUtils.randomAlphanumeric(16)
      val clientSecret = RandomStringUtils.randomAlphanumeric(10)
      val regAccessToken = RandomStringUtils.randomAlphanumeric(10)
      val regClientUri =  RandomStringUtils.randomAlphanumeric(16)
      var jsonClientInfo : JsObject = Json.obj( "client_id" -> clientId,
        "client_secret" -> clientSecret,
        "registration_access_token" -> regAccessToken,
        "registration_client_uri" -> ("https://" + request.host + "/oidcop/client/" + regClientUri)
      )

      val jsonRequest : JsObject = request.body.as[JsObject]
      var fields : scala.collection.mutable.Map[String, Any] = Client.defaultFields.map{ case (x, y) => {
        jsonRequest \ x match {
          case JsNull => Logger.trace(x + " = none***\n");if(0 == x.compare("id_token_signed_response_alg")) {jsonClientInfo = jsonClientInfo  + ("id_token_signed_response_alg", JsString("RS256"));x -> "RS256"} else x-> None
          case yVal : JsUndefined => Logger.trace(x + " = undefined***");if(0 == x.compare("id_token_signed_response_alg")) {jsonClientInfo = jsonClientInfo  + ("id_token_signed_response_alg", JsString("RS256"));x -> "RS256"} else x-> None
          //        case yVal : JsArray => Logger.trace(x + " = array***\n" + yVal.value.mkString("|") + "\n"); x-> yVal.value.mkString("|")
          //        case yVal : JsArray => Logger.trace(x + " = array***\n" + yVal.value.mkString("|") + "\n"); x-> yVal.value.map( f => {f.as[String]}).mkString("|")

          case yVal : JsArray => Logger.trace(x + " = array***\n" + yVal.value.mkString("|") + "\n")
            if(x.equals("redirect_uris")) {
              yVal.value.map( uri => if(uri.as[String].contains("#")) throw OidcException("invalid_redirect_uri", "invalid redirect_uri value"))
            }
            x-> yVal.value.map( f => {f match {
              case fVal : JsString => Logger.trace("array string " + fVal.value);fVal.value
              case fVal => Logger.trace("array unknown class =" + fVal.getClass);fVal.toString
            }
            }).mkString("|")


          case yVal : JsBoolean => Logger.trace(x + " = boolean*** " + yVal.toString + "\n"); yVal.value match { case true => x->1; case false => x->0}
          case yVal : JsString => Logger.trace(x + "= " + yVal.value + "\n"); x -> yVal.value
          case yVal  => Logger.trace(x + "= " + yVal.toString + "\n"); x -> yVal.toString
        }
      }}

      val jsonRequestKeys : scala.collection.Set[String] = jsonRequest.keys;
      if(!jsonRequestKeys.contains("redirect_uris"))
        throw OidcException("invalid_redirect_uri", "no redirect uris");
      if(jsonRequestKeys.contains("sector_identifier_uri")) {
        val sectorUris : String = getSSLURLContents((jsonRequest \ "sector_identifier_uri").as[String])
        if(sectorUris.isEmpty)
          throw OidcException("invalid_client_metadata", "empty sector identifier uri contents")
        val sectorUrisJson : Array[String] = Json.parse(sectorUris).as[JsArray].as[Array[String]]
        Logger.trace("sectorUrisJson = " + sectorUrisJson.toSeq.toString())
        val redirectUrisJson : Array[String] = (jsonRequest \ "redirect_uris").as[JsArray].as[Array[String]]
        Logger.trace("redirectUrisJson = " + redirectUrisJson.toSeq.toString)
        if(sectorUrisJson.length != redirectUrisJson.length)
          throw OidcException("invalid_client_metadata", "invalid sector_identifier_uri content")
        if(!sectorUrisJson.forall(x => redirectUrisJson.contains(x)))
          throw OidcException("invalid_client_metadata", "invalid sector_idenfifier_uri content")

      }

      Logger.trace("request fields = " + fields.toString())
      Logger.trace("request json = " + jsonRequest.toString)
      fields("client_id") = clientId
      fields("client_secret") = clientSecret
      fields("registration_access_token") = regAccessToken
      fields("registration_client_uri_path") = regClientUri
      val client = Client(fields)
      Client.insert(client)
      val updatedInfo : JsObject = (jsonRequest ++ jsonClientInfo).as[JsObject]
      Logger.trace("response json = " + updatedInfo.toString)
      Ok(Json.prettyPrint(updatedInfo)).as(JSON)
    }
    catch {
      case e : OidcException => Logger.trace(e.getStackTraceString); sendError("", e.error, e.desc)
      case e : Throwable => sendError("", "invalid_client_metadata", e.getStackTraceString)
    }
  }


  def clientinfo(clientUri : String) = Action { implicit request =>
    try {
      var accessToken : String = getAccessTokenFromRequest(request)
      if(accessToken.isEmpty)
        throw BearerException("invalid_token", "no access token")
      val client : Option[Client] = Client.findByRegUriAndToken(clientUri, accessToken)
      client match {
        case None =>  throw OidcException("invalid_client_id")
        case Some(_) => {

          val arrKeys : Seq[String] = Seq("redirect_uris", "response_types", "grant_types", "contacts", "post_logout_redirect_uris", "request_uris")
          val specialKeys : Seq[String] = Seq("id", "client_secret_expires_at", "client_secret")
          val filtered : scala.collection.mutable.Map[String, Any] = client.get.fields.filter( {case(x, y) =>
            if(!specialKeys.contains(x)) {
              y.asInstanceOf[Option[Any]] match {
                case None => false
                case Some(_) => true
              }
            } else
              false
          } )
          Logger.trace("filter = " + filtered)


          val params = filtered.map {
            case (x, y) => (x match { case "registration_client_uri_path" => "registration_client_uri"
                                      case _ => x
                                    },
                            {
                            val yy : Any = y.asInstanceOf[Option[Any]].getOrElse("")
                            yy match {
                              case yval : Int => Json.toJsFieldJsValueWrapper(yval)
                              case yval : Long => Json.toJsFieldJsValueWrapper(yval)
                              case yval : String => {
                                x match {
                                  case "registration_client_uri_path" =>  Json.toJsFieldJsValueWrapper("https://" + request.host + "/oidcop/client/" + yval)
                                  case _ =>  if(yval.contains("|") || arrKeys.contains(x))
                                      Json.toJsFieldJsValueWrapper(yval.split('|'))
                                    else Json.toJsFieldJsValueWrapper(yval)
                                }
                              }
                              case yval : Boolean => Json.toJsFieldJsValueWrapper(yval)
                            }
                            }
              )
          }
          var jsonParams : JsObject = Json.obj(params.toSeq:_*)
          Ok(Json.prettyPrint(jsonParams)).as(JSON)
        }
      }

    }
    catch {
      case e : OidcException => Logger.trace("clientinfo exception " + e + e.getStackTraceString); sendError("", e.error, e.desc, "", "", true, UNAUTHORIZED)
      case e : BearerException => Logger.trace("clientinfo exception " + e); sendBearerError(e.error, e.desc, FORBIDDEN)
      case e : Throwable => Logger.trace("clientinfo Exception " + e);sendError("", "invalid_request", e.getStackTraceString, "", "", true, FORBIDDEN)
    }

 }

  def auth = StackAction { implicit request =>
    val user : Option[User] = loggedIn

    user match {
//      case None => authenticationFailed(request)
//      case x : Option[User] => Ok(request.session.toString + "\n" + user.toString)
      case x : Option[User] => handleAuth(request, user)
    }



  }

  /*
   * sends error output
   *
   */
  def sendError(url : String, error : String, desc : String = "", error_uri : String = "", state : String = "", isQuery : Boolean = true, httpCode : Int = BAD_REQUEST) : Result = {
    Logger.trace("sendError " + error + " : " + desc + " : " + state + " : " + httpCode + "\n")
    var params : scala.collection.mutable.Map[String, String] = scala.collection.mutable.Map("error" -> error)
    if(!desc.isEmpty)
      params("error_description") = desc
    if(!error_uri.isEmpty)
      params("error_uri") = error_uri
    if(!state.isEmpty)
      params("state") = state

    if(!url.isEmpty) {
      var separator : String = "?"
      if(!isQuery)
        separator = "#"

      val redir : String = String.format("%s%s%s", url, separator, params.map(x => x._1 + "=" + x._2 ).mkString("&"))
      Logger.trace("Redirecting to " + redir)
      Redirect(redir, FOUND)
    } else {
      val json : JsObject = JsObject(params.map(x=> x._1 -> JsString(x._2)).toSeq)
      val headers : Map[String, String] = Map("Cache-Control"->"no-store", "Pragma"->"no-cache")
      val respFunction = httpCode match {
        case BAD_REQUEST => BadRequest
        case UNAUTHORIZED => Unauthorized
        case FORBIDDEN=> Forbidden
        case NOT_FOUND => NotFound
        case METHOD_NOT_ALLOWED => MethodNotAllowed
        case _ => BadRequest
      }
      respFunction(Json.prettyPrint(json)).as(JSON).withHeaders(headers.toSeq:_*)
    }
  }

  /*
   * Sends Bearer Error
      '400' => 'Bad Request',
      '401' => 'Unauthorized',
      '403' => 'Forbidden',
      '404' => 'Not Found',
      '405' => 'Method Not Allowed'

   */
  def sendBearerError(error : String, desc : String = "", httpCode : Int = BAD_REQUEST) : Result = {
    Logger.trace("sendBearerError " + error + " : " + desc  + " : " + httpCode)
    val description = desc match {
      case "" => ""
      case e : String => " error_description='" + e + "'"
    }
    val headers : Map[String, String] = Map("WWW-Authenticate"-> {"Bearer error='" + error + "'" + description} )
    val respFunction = httpCode match {
      case BAD_REQUEST => BadRequest
      case UNAUTHORIZED => Unauthorized
      case FORBIDDEN=> Forbidden
      case NOT_FOUND => NotFound
      case METHOD_NOT_ALLOWED => MethodNotAllowed
      case _ => BadRequest
    }
    respFunction("").withHeaders(headers.toSeq:_*)
  }


  def getRequestParamsAsJson(client : Client, req : Map[String, String]) : JsObject = {
    val specialKeys : Seq[String] = Seq("claims", "request", "request_uri")
    val filtered : Map[String, String] = req.filterKeys(p => !specialKeys.contains(p))

    val params = filtered.map {
      case (x, y) => (x,Json.toJsFieldJsValueWrapper(y))
    }

    var jsonParams : JsObject = Json.obj(params.toSeq:_*)
    val claims = req.getOrElse("claims", "")
    if(!claims.isEmpty)
      jsonParams = jsonParams ++ Json.obj("claims"->Json.parse(claims).as[JsObject])

    var request = req.getOrElse("request", "")
    val requestUri = req.getOrElse("request_uri", "")
    if(!requestUri.isEmpty)
      request = getSSLURLContents(requestUri)
    if(!request.isEmpty){
      val jwks_uri = client.fields("jwks_uri").asInstanceOf[Option[String]].get
      Logger.trace("client fields = " + client.fields)
      Logger.trace("client jwks_uri = " + jwks_uri)
      val jwks : String = getSSLURLContents(client.fields("jwks_uri").asInstanceOf[Option[String]].get)
      Logger.trace("jwks = " + jwks)
      val jwkSet = JWKSet.parse(jwks)
      Logger.trace("jwkset = " + jwkSet.toString)

      var joseObject : JOSEObject = JOSEObject.parse(request)
      var joseHeader : ReadOnlyHeader = joseObject.getHeader
      Logger.trace("header = " + joseHeader.toString + " type = " + joseHeader.getType)

      val sig : String  =  client.fields("request_object_signing_alg").asInstanceOf[Option[String]].getOrElse("")
      val clientSecret : String  =  client.fields("client_secret").asInstanceOf[Option[String]].getOrElse("")
      if(joseObject.isInstanceOf[JWEObject]) {
        request = decryptJWE(request)
        if(!request.isEmpty) {
          joseObject = JOSEObject.parse(request)
          joseHeader = joseObject.getHeader
          Logger.trace("header = " + joseHeader.toString + " type = " + joseHeader.getType)
        }
      }
      if(joseObject.isInstanceOf[JWSObject]) {
        val verified = verifyJWS(request, sig,clientSecret, jwkSet)
        if(verified) {
          val payload : JsObject = Json.parse(joseObject.getPayload.toString).as[JsObject]
          Logger.trace("req payload = " + payload.toString)
          jsonParams = jsonParams ++ payload
        } else {
          jsonParams = Json.obj()
        }
      }
    }
    Logger.trace("final req = " + jsonParams.toString)

    Logger.trace("idtoken claims = " + getIdTokenClaims(jsonParams))
    Logger.trace("userinfo claims = " + getUserInfoClaims(jsonParams))
    jsonParams
  }


  def getRequestClaims(req : JsObject, subKey : String) : Seq[String] = {
    val json : Option[JsObject] = (req \ "claims" \ subKey).asOpt[JsObject]

    json match {
      case None => Seq()
      case Some(_) => {
        json.get.keys.toSeq
      }
    }
  }

 def getUserInfoClaims(req : JsObject) : Seq[String] = {
   var scopeClaims : Seq[String] = Seq()
   val scopes = (req \ "scope").asOpt[String].getOrElse("").split(' ')
   if(!scopes.isEmpty) {
     if(scopes.contains("profile"))
       scopeClaims = scopeClaims ++ Seq("name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at")
     if(scopes.contains("email"))
       scopeClaims = scopeClaims ++ Seq("email", "email_verified")
     if(scopes.contains("address"))
       scopeClaims = scopeClaims ++ Seq("address")
     if(scopes.contains("phone"))
       scopeClaims = scopeClaims ++ Seq("phone_number", "phone_number_verified")
   }
   val userInfoClaims : Seq[String] = getRequestClaims(req, "userinfo")
   Logger.trace("scope claims = " + scopeClaims + " count : " + scopeClaims.length)
   Logger.trace("userinfo claims = " + userInfoClaims + " count : " + userInfoClaims.length)
   val allClaims : Seq[String] = (scopeClaims ++ userInfoClaims).toSet.toSeq
   Logger.trace("all claims = " + allClaims + " count : " + allClaims.length)

   allClaims
 }

  def getIdTokenClaims(req : JsObject) : Seq[String] = {
    val idTokenClaims = getRequestClaims(req, "id_token")
    ((req \ "max_age").asOpt[String].getOrElse("none")) match {
      case "none"  => idTokenClaims
      case maxAge : String => if(!idTokenClaims.contains("auth_time")) idTokenClaims :+ "auth_time"; idTokenClaims
    }
  }

  def getAllRequestedClaims(req : JsObject) : Seq[String] = {
    getUserInfoClaims(req) ++ getIdTokenClaims(req) ++ Seq("sub")
  }

  def handleAuth(request: Request[AnyContent], user : Option[User]) : Result =  {
    var redirectUri : String = ""
    var state = ""
    var isQuery = true
    try {
      state = request.getQueryString("state").getOrElse("")
      redirectUri = request.getQueryString("redirect_uri").getOrElse("")
      if(redirectUri.isEmpty)
        throw OidcException("invalid_request", "no redirect_uri")

      val client = Client.findByClientId(request.getQueryString("client_id").getOrElse(""))
      if(client == None)
        throw OidcException("invalid_request", "no client")

      val registeredRedirectUris : Seq[String] = client.get.fields.asInstanceOf[scala.collection.mutable.Map[String, Option[Any]]].getOrElse("redirect_uris", Some("")).get.asInstanceOf[String].split('|')
      Logger.trace("registered redirect_uris = " + registeredRedirectUris.toString)
      Logger.trace("redirect_uri = " + redirectUri)

      if(!registeredRedirectUris.contains(redirectUri)) {
        Logger.trace("unregistered redirect_uri")
        val index = redirectUri.indexOf('?'.toInt)
        if(index != -1){
          Logger.trace("redirect_uri has query")
          var redirectUriNoQuery : String = redirectUri.substring(0, index)
          if(!registeredRedirectUris.contains(redirectUriNoQuery)) {
            redirectUri = ""
            throw OidcException("invalid_request", "unregistered redirect uri")
          }
        } else {
          Logger.trace("no query in redirect_uri")
          redirectUri = ""
          throw OidcException("invalid_request", "unregistered redirect uri")
        }
      } else
        Logger.trace("redirect_uri is registered")

      var queryString : Map[String, Seq[String]] = Map()
      var prompt : Array[String] = (request.getQueryString("prompt").getOrElse("")).split(' ').filter(p => !p.isEmpty)
      if(prompt.contains("none")) {
        if(user.equals(None) || (prompt.length > 1))
          throw OidcException("interaction_required", "uable to show UI with prompt set to none")
      }
      var idTokenHint : String = request.getQueryString("id_token_hint").getOrElse((""))
      var requestedUserId : String = ""
      var displayUserId : String = ""
      if(!idTokenHint.isEmpty) {
        var jsonParams : JsObject = Json.obj()
        var joseObject : JOSEObject = JOSEObject.parse(idTokenHint)
        var joseHeader : ReadOnlyHeader = joseObject.getHeader
        Logger.trace("header = " + joseHeader.toString + " type = " + joseHeader.getType)
        val sig : String  =  client.get.fields("request_object_signing_alg").asInstanceOf[Option[String]].getOrElse("")
        val clientSecret : String  =  client.get.fields("client_secret").asInstanceOf[Option[String]].getOrElse("")
        if(joseObject.isInstanceOf[JWEObject]) {
          idTokenHint = decryptJWE(idTokenHint)
          if(!idTokenHint.isEmpty) {
            joseObject = JOSEObject.parse(idTokenHint)
            joseHeader = joseObject.getHeader
            Logger.trace("header = " + joseHeader.toString + " type = " + joseHeader.getType)
          }
        }
        if(joseObject.isInstanceOf[JWSObject]) {
          val jwkSet : JWKSet = JWKSet.parse(getFileContents(Play.application.getFile("public/keys/2048.jwk").getAbsolutePath))
          val verified = verifyJWS(idTokenHint, sig,clientSecret, jwkSet)
          if(verified) {
            val payload : JsObject = Json.parse(joseObject.getPayload.toString).as[JsObject]
            Logger.trace("req payload = " + payload.toString)
            jsonParams = jsonParams ++ payload
          } else {
            jsonParams = Json.obj()
          }
        }

        displayUserId = (jsonParams \ "sub").asOpt[String].getOrElse("")
        if(displayUserId.isEmpty)
          throw OidcException("invalid_request", "invalid id_token_hint")
        requestedUserId = unWrapUserId(displayUserId)
        val tempAccount : Option[Account] = Account.findByLogin(requestedUserId)
        if(tempAccount == None)
          throw OidcException("invalid_request", "invalid user in id_token_hint")
        if(!requestedUserId.isEmpty && !user.equals(None)) {
          if((requestedUserId != user.get.login)) {
            if(prompt.contains("none"))
              throw OidcException("interaction_required", "requested account differs from logged in account, no UI requested")
            else
              return authenticationFailed(request)
          }
        }
      }


      var responseTypes : Array[String] = (request.getQueryString("response_type").getOrElse("")).split(' ').filter(p => !p.isEmpty)
      Logger.trace("responseTypes = " + responseTypes.toSeq.toString)
      if(responseTypes.isEmpty)
        throw OidcException("invalid_request", "no response types")
      val nonce = request.getQueryString("nonce").getOrElse("")
      if(responseTypes.contains("token") && nonce.isEmpty)
        throw OidcException("invalid_request", "no nonce")

      val scopes : Array[String] = request.getQueryString("scope").getOrElse("").split(' ').filter(p => !p.isEmpty)
      if(scopes.isEmpty)
        throw OidcException("invalid_request", "no scope")
      if(!scopes.contains("openid"))
        throw OidcException("invalid_scope", "no openid scope")

      val maxAge : Int = request.getQueryString("max_age").getOrElse(client.get.fields.get("default_max_age").asInstanceOf[Option[Option[Int]]].get.getOrElse(0).toString).toInt
      Logger.trace("max_age = " + maxAge)

      if((prompt.contains("login") && !request.flash.get("relogin").getOrElse("0").equals("1")) || user.equals(None))
        return authenticationFailed(request)

      val cacheParams : Map[String, Any] = Cache.getAs[Map[String, Any]]("session."+request.session.get("sessionid").get).getOrElse(Map())
      val authTime = cacheParams("auth_time").asInstanceOf[DateTime]
      val minAuthTime = DateTime.now.minusSeconds(maxAge).withMillisOfSecond(0)
      Logger.trace("auth time = " + authTime + "\nnow = " + DateTime.now + "\nmin auth time = " + minAuthTime)

      if(maxAge > 0) {
        if(minAuthTime.isAfter(authTime)) {
          if(prompt.contains("none"))
            throw OidcException("login_required", "prompt is set to none but max_age requires relogin")
          else
            return authenticationFailed(request)
        }
      }

      val cacheSessionId = "session." + request.session.get("sessionid").get
      val reqGet = request.queryString.map({case(x,y:Seq[String]) => x-> y.mkString(",")})
      val requestedClaimsJson = getRequestParamsAsJson(client.get, reqGet)
      val sessionParams : Map[String, Any] = Cache.getAs[Map[String, Any]](cacheSessionId).getOrElse(Map())

      val newSessionParams = sessionParams ++ Map("get"->reqGet, "reqJson" -> requestedClaimsJson)
      Cache.set(cacheSessionId, newSessionParams)
      Logger.trace("sessionid = session." + request.session.get("sessionid").get)
      Logger.trace("setting json obj = " + requestedClaimsJson)
      val requestedClaimsJson1 : JsObject = newSessionParams("reqJson").asInstanceOf[JsObject]
      Logger.trace("json request = " + requestedClaimsJson1)
      val requestedClaims : Seq[String] = getAllRequestedClaims(requestedClaimsJson)
      val trustedSite : Option[TrustedSite] = TrustedSite.findByAccountClient(user.get.login, client.get.fields("client_id").asInstanceOf[Option[String]].getOrElse(""));
      if(prompt.contains("consent") || (trustedSite == None)) {
        Logger.trace("waiting for consent")
        val logo_uri : String = client.get.fields.get("logo_uri").asInstanceOf[Option[Option[String]]].get.getOrElse("")
        val policy_uri : String = client.get.fields.get("policy_uri").asInstanceOf[Option[Option[String]]].get.getOrElse("")
        return Ok(views.html.confirm(requestedClaims, logo_uri, policy_uri))
      }
      else
        sendResponse(request, user.get, true)
    }
    catch {
      case e : NoSuchElementException => { Logger.trace(e.getStackTraceString); sendError(redirectUri, "invalid_request", e.toString) }
      case e : OidcException => Logger.trace(e.getStackTraceString); sendError(redirectUri, e.error, e.desc, e.error_uri, state, isQuery)
      case e : Throwable => sendError(redirectUri, "unknown_error : " + e, e.getStackTraceString)
    }

  }


  def sendResponse(request : Request[AnyContent], user : User, authorize : Boolean) : Result =  {
    var redirectUri : String = ""
    var state = ""
    var isQuery = true

    try {
      Logger.trace("sessionid = session." + request.session.get("sessionid").get)
      val cacheParams : Map[String, Any] = Cache.getAs[Map[String, Any]]("session."+request.session.get("sessionid").get).getOrElse(Map())
      val reqGet : Map[String, String] = cacheParams("get").asInstanceOf[Map[String, String]]
      val requestedClaimsJson : JsObject = cacheParams("reqJson").asInstanceOf[JsObject] ++ Json.obj("sessionid"->request.session.get("sessionid").get)
      Logger.trace("json request = " + requestedClaimsJson)
      var queryString : Map[String, Seq[String]] = Map()

      val state = (requestedClaimsJson \ "state").asOpt[String].getOrElse("")
      val nonce = (requestedClaimsJson \ "nonce").asOpt[String].getOrElse("")
      redirectUri = (requestedClaimsJson \ "redirect_uri").asOpt[String].get
      val client =  Client.findByClientId((requestedClaimsJson \ "client_id").asOpt[String].get)
      if(client == None)
        throw OidcException("invalid_request", "no client")

      var responseTypes : Array[String] = ((requestedClaimsJson \ "response_type").asOpt[String].getOrElse("")).split(' ').filter(p => !p.isEmpty)
      if(responseTypes.isEmpty)
        throw OidcException("invalid_request", "no response types")

      val scopes : Array[String] = (requestedClaimsJson \ "scope").asOpt[String].getOrElse("").split(' ').filter(p => !p.isEmpty)
      if(scopes.isEmpty)
        throw OidcException("invalid_request", "no scope")
      if(!scopes.contains("openid"))
        throw OidcException("invalid_scope", "no openid scope")
      if(!authorize)
        throw OidcException("access_denied", "User denied access")


      var codeVal = ""
      var tokenVal = ""

      var allowedClaims : Seq[String] = getAllRequestedClaims(requestedClaimsJson)
      if(responseTypes.contains("code")) {
        val codeInfo : JsObject = Token.create_token_info(user.login, "Default", allowedClaims.toList, JsObject(reqGet.map({case(x,y) => (x, JsString(y))}).toSeq), requestedClaimsJson)
        codeVal = (codeInfo \ "name").asOpt[String].get
        val code = Token(0, user.id, codeVal, Some(0), client.get.fields.get("client_id").asInstanceOf[Option[String]], None, Some(DateTime.now), Some(DateTime.now.plusDays(1)), Some(codeInfo.toString))
        Token.insert(code)
        queryString += "code" -> Seq(codeVal)
      }

      if(responseTypes.contains("token")) {
        val tokenInfo : JsObject = Token.create_token_info(user.login, "Default", allowedClaims.toList, JsObject(reqGet.map({case(x,y) => (x, JsString(y))}).toSeq), requestedClaimsJson)
        tokenVal = (tokenInfo \ "name").asOpt[String].get
        val token = Token(0, user.id, tokenVal, Some(1), client.get.fields.get("client_id").asInstanceOf[Option[String]], None, Some(DateTime.now), Some(DateTime.now.plusDays(1)), Some(tokenInfo.toString))
        Token.insert(token)
        queryString += (("access_token", Seq(tokenVal)), ("token_type", Seq("Bearer")),  ("expires_in",Seq("3600")) )
      }

      if(responseTypes.contains("id_token")) {
        val cid : Option[String] = client.get.fields.get("client_id").asInstanceOf[Option[Option[String]]].get
        val idTokenClaimsList = getIdTokenClaims((requestedClaimsJson).as[JsObject] )
        Logger.trace("idtoken claims = " + idTokenClaimsList)
        val persona = Persona.findByAccountPersona(user, "Default").get
        val idTokenClaims : Map[String, Any] = idTokenClaimsList.filter(p => allowedClaims.contains(p)).map{ claimName =>
          claimName match {
            case "phone_number_verified" | "email_verified" => persona.fields.getOrElse(claimName, Some(false)).asInstanceOf[Option[Boolean]].get match {
              case verified : Boolean => (claimName, verified)
            }
            // TODO Add ACR values
            case "address" => val addressMap = new java.util.HashMap[String, java.lang.Object]; addressMap.put("formatted", persona.fields.getOrElse(claimName, Some("")).asInstanceOf[Option[String]].get);(claimName, addressMap)
            case "updated_at" => (claimName, persona.fields.getOrElse(claimName, Some(DateTime.now)).asInstanceOf[Option[DateTime]].get)
            case "auth_time" => (claimName, cacheParams("auth_time").asInstanceOf[DateTime].getMillis)
            case field : String => (field, persona.fields.getOrElse(field, Some("")).asInstanceOf[Option[String]].get)
          }
        }.toMap

        val sig : String = client.get.fields("id_token_signed_response_alg").asInstanceOf[Option[String]].getOrElse("")
        val alg : String = client.get.fields("id_token_encrypted_response_alg").asInstanceOf[Option[String]].getOrElse("")
        val enc : String = client.get.fields("id_token_encrypted_response_enc").asInstanceOf[Option[String]].getOrElse("")
        val jwksUri : String = client.get.fields("jwks_uri").asInstanceOf[Option[String]].getOrElse("")
        val clientSecret : String = client.get.fields("client_secret").asInstanceOf[Option[String]].getOrElse("")

        val hashAlg = "SHA-" + sig.substring(2)
        val hashBitLen : Int = sig.substring(2).toInt
        val hashLen =  hashBitLen / (8 * 2)
        val md : MessageDigest = MessageDigest.getInstance(hashAlg)
        var codeHash = ""
        if(!codeVal.isEmpty)
          codeHash = Base64URL.encode(md.digest(codeVal.getBytes).slice(0, hashLen)).toString
        var accessTokenHash = ""
        if(!tokenVal.isEmpty)
          accessTokenHash = Base64URL.encode(md.digest(tokenVal.getBytes).slice(0, hashLen)).toString
        val idt = signEncrypt(makeIdToken(wrapUserId(client.get, user.login), cid.get, idTokenClaims, nonce, codeHash, accessTokenHash), sig, alg, enc, jwksUri, clientSecret)
        queryString += "id_token" -> Seq(idt )
      }

      if(!state.isEmpty)
        queryString += "state" -> Seq(state)

      val uri = new URI(redirectUri)
      val sessionId = request.session.get("sessionid").getOrElse("")
      if(!sessionId.isEmpty) {
        val port = uri.getPort match {
          case -1 => ""
          case _ => ":" + uri.getPort
        }
        val origin : String = String.format("%s://%s%s", uri.getScheme, uri.getHost, port)
        val salt : String = RandomStringUtils.randomAlphanumeric(16)
        val digestString = String.format("%s%s%s%s", client.get.fields("client_id").asInstanceOf[Option[String]].get, origin, sessionId, salt)
        val md : MessageDigest = MessageDigest.getInstance("SHA-256")
        md.update(digestString.getBytes())
        val byteData : Array[Byte] = md.digest
        val sessionState =  byteData.map { data => Integer.toString((data & 0xff) + 0x100, 16).substring(1) }.mkString + "." + salt
        queryString += "session_state" -> Seq(sessionState)
      }
      var queryParams = ""
      var fragmentParams = ""
      if(uri.getQuery != null)
        queryParams = uri.getQuery
      if(responseTypes.contains("token") || responseTypes.contains("id_token"))
        fragmentParams = queryString.map{case(x,y) => x + "=" + y.mkString(",")}.mkString("&")
      else {
        if(!queryParams.isEmpty)
          queryParams = queryParams + "&" + queryString.map{case(x,y) => x + "=" + y.mkString(",")}.mkString("&")
        else
          queryParams = queryString.map{case(x,y) => x + "=" + y.mkString(",")}.mkString("&")
      }
      val redirURL = URIUtils.createURI(uri.getScheme, uri.getHost, uri.getPort, uri.getPath, queryParams, fragmentParams)
      Redirect(redirURL.toASCIIString, FOUND)
    }
    catch {
      case e : NoSuchElementException => {Logger.trace("NoSuchElementException" + e + e.getStackTraceString); sendError(redirectUri, "invalid_request") }
      case e : OidcException => Logger.trace(e.getStackTraceString); sendError(redirectUri, e.error, e.desc, e.error_uri, state, isQuery)
      case e : Throwable => sendError(redirectUri, "unknown_error : " + e, e.getStackTraceString)
    }
  }


  def confirm = StackAction { implicit request =>
    var redirectUri : String = ""
    var state = ""
    var isQuery = true
    val user : Option[User] = loggedIn

    try {

      val postForm : Option[Map[String, Seq[String]]] = request.body.asFormUrlEncoded
      Logger.trace("post form = " + postForm)
      val cacheParams : Map[String, Any] = Cache.getAs[Map[String, Any]]("session."+request.session.get("sessionid").get).getOrElse(Map())
      val reqGet : Map[String, String] = cacheParams("get").asInstanceOf[Map[String, String]]
      val requestedClaimsJson : JsObject = cacheParams("reqJson").asInstanceOf[JsObject] ++ Json.obj("sessionid"->request.session.get("sessionid").get)

      val state = (requestedClaimsJson \ "state").asOpt[String].getOrElse("")
      redirectUri = (requestedClaimsJson \ "redirect_uri").asOpt[String].get
      val client : Option[Client] =  Client.findByClientId((requestedClaimsJson \ "client_id").asOpt[String].get)
      if(client == None)
        throw OidcException("invalid_request", "no client")
      val trustedSite : Option[TrustedSite] = TrustedSite.findByAccountClient(loggedIn.get.login, client.get.fields("client_id").asInstanceOf[Option[String]].get)
      val persona : Option[Persona] = Persona.findByAccountPersona(user.get, "Default")
      val authorize : Boolean = postForm.get.getOrElse("authorize", Seq("deny"))(0).equals("authorize")
      postForm.get("trust")(0) match {
        case "always" => {
          trustedSite match {
            case None => {
              if(authorize) {
                val newSite : TrustedSite = TrustedSite(0, user.get.id, persona.get.fields("id").asInstanceOf[Long], client.get.fields("client_id").asInstanceOf[Option[String]].get)
                TrustedSite.insert(newSite)
              }
            }
            case Some(_) => {
              if(!authorize)
                TrustedSite.delete(trustedSite.get.id)
            }
          }
        }
        case _ => {
          trustedSite match {
            case None =>
            case Some(_) => TrustedSite.delete(trustedSite.get.id)
          }
        }
      }

      sendResponse(request, user.get, authorize)
    }
    catch {
      case e : NoSuchElementException => {Logger.trace("NoSuchElementException" + e + " " + e.getStackTraceString); sendError(redirectUri, "invalid_request") }
      case e : OidcException => Logger.trace(e.getStackTraceString); sendError(redirectUri, e.error, e.desc, e.error_uri, state, isQuery)
      case e : Throwable => sendError(redirectUri, "unknown_error : " + e, e.getStackTraceString)
    }

  }


  def confirm1 = StackAction { implicit request =>
    var redirectUri : String = ""
    var state = ""
    var isQuery = true
    val user : Option[User] = loggedIn



    try {

      Logger.trace("sessionid = session." + request.session.get("sessionid").get)
      val cacheParams : Map[String, Any] = Cache.getAs[Map[String, Any]]("session."+request.session.get("sessionid").get).getOrElse(Map())
      val reqGet : Map[String, String] = cacheParams("get").asInstanceOf[Map[String, String]]
      val requestedClaimsJson : JsObject = cacheParams("reqJson").asInstanceOf[JsObject] ++ Json.obj("sessionid"->request.session.get("sessionid").get)

//      val reqGet : Map[String, String] = Cache.getAs[Map[String, String]]("session."+request.session.get("sessionid").get+".get").get
//      val requestedClaimsJson : JsObject = Cache.getAs[JsObject]("session."+request.session.get("sessionid").get).get
      Logger.trace("json request = " + requestedClaimsJson)


      val postForm : Option[Map[String, Seq[String]]] = request.body.asFormUrlEncoded
      Logger.trace("post form = " + postForm)
//
//      redirectUri = request.getQueryString("redirect_uri").getOrElse("")
//      val client = Client.findByClientId(request.getQueryString("client_id").getOrElse(""))
//      if(client == None)
//        throw OidcException("invalid_request", "no client")
//
//
      var queryString : Map[String, Seq[String]] = Map()
//      var responseTypes : Array[String] = (request.getQueryString("response_type").getOrElse("")).split(' ').filter(p => !p.isEmpty)
//      if(responseTypes.isEmpty)
//        throw OidcException("invalid_request", "no response types")
//
//      val scopes : Array[String] = request.getQueryString("scope").getOrElse("").split(' ').filter(p => !p.isEmpty)
//      if(scopes.isEmpty)
//        throw OidcException("invalid_request", "no scope")
//      if(!scopes.contains("openid"))
//        throw OidcException("invalid_scope", "no openid scope")
//
//      val state = request.getQueryString("state").getOrElse("")
//      val nonce = request.getQueryString("nonce").getOrElse("")

      val state = (requestedClaimsJson \ "state").asOpt[String].getOrElse("")
      val nonce = (requestedClaimsJson \ "nonce").asOpt[String].getOrElse("")
      redirectUri = (requestedClaimsJson \ "redirect_uri").asOpt[String].get
      val client =  Client.findByClientId((requestedClaimsJson \ "client_id").asOpt[String].get)
      if(client == None)
        throw OidcException("invalid_request", "no client")

      var responseTypes : Array[String] = ((requestedClaimsJson \ "response_type").asOpt[String].getOrElse("")).split(' ').filter(p => !p.isEmpty)
      if(responseTypes.isEmpty)
        throw OidcException("invalid_request", "no response types")

      val scopes : Array[String] = (requestedClaimsJson \ "scope").asOpt[String].getOrElse("").split(' ').filter(p => !p.isEmpty)
      if(scopes.isEmpty)
        throw OidcException("invalid_request", "no scope")
      if(!scopes.contains("openid"))
        throw OidcException("invalid_scope", "no openid scope")

      postForm.get("authorize")(0) match {
        case "deny" =>  throw OidcException("access_denied", "User denied access")
        case _ =>
      }

      postForm.get("trust")(0) match {
        case "always" =>
        case _ =>
      }
      var codeVal = ""
      var tokenVal = ""
      var allowedClaims : Seq[String] = getAllRequestedClaims(requestedClaimsJson)
      if(responseTypes.contains("code")) {
        //        codeVal = RandomStringUtils.randomAlphanumeric(20)
        val codeInfo : JsObject = Token.create_token_info(user.get.login, "Default", allowedClaims.toList, JsObject(reqGet.map({case(x,y) => (x, JsString(y))}).toSeq), requestedClaimsJson)
        codeVal = (codeInfo \ "name").asOpt[String].get
        val code = Token(0, 1, codeVal, Some(0), client.get.fields.get("client_id").asInstanceOf[Option[String]], None, Some(DateTime.now), Some(DateTime.now.plusDays(1)), Some(codeInfo.toString))
        Token.insert(code)
        queryString += "code" -> Seq(codeVal)
      }

      if(responseTypes.contains("token")) {
        val tokenInfo : JsObject = Token.create_token_info(user.get.login, "Default", allowedClaims.toList, JsObject(reqGet.map({case(x,y) => (x, JsString(y))}).toSeq), requestedClaimsJson)
        tokenVal = (tokenInfo \ "name").asOpt[String].get
        val token = Token(0, 1, tokenVal, Some(1), client.get.fields.get("client_id").asInstanceOf[Option[String]], None, Some(DateTime.now), Some(DateTime.now.plusDays(1)), Some(tokenInfo.toString))
        Token.insert(token)
        queryString += "access_token" -> Seq(tokenVal)
      }

      if(responseTypes.contains("id_token")) {
        val cid : Option[String] = client.get.fields.get("client_id").asInstanceOf[Option[Option[String]]].get
        val idTokenClaimsList = getIdTokenClaims((requestedClaimsJson).as[JsObject] )
        Logger.trace("idtoken claims = " + idTokenClaimsList)
        val persona = Persona.findByAccountPersona(user.get, "Default").get
        val idTokenClaims : Map[String, Any] = idTokenClaimsList.filter(p => allowedClaims.contains(p)).map{ claimName =>
          claimName match {
            case "phone_number_verified" | "email_verified" => persona.fields.getOrElse(claimName, Some(false)).asInstanceOf[Option[Boolean]].get match {
              case verified : Boolean => (claimName, verified)
            }
            // TODO Add ACR values
            case "address" => val addressMap = new java.util.HashMap[String, java.lang.Object]; addressMap.put("formatted", persona.fields.getOrElse(claimName, Some("")).asInstanceOf[Option[String]].get);(claimName, addressMap)
            case "updated_at" => (claimName, persona.fields.getOrElse(claimName, Some(DateTime.now)).asInstanceOf[Option[DateTime]].get)
            case "auth_time" => (claimName, cacheParams("auth_time").asInstanceOf[DateTime].getMillis)
            case field : String => (field, persona.fields.getOrElse(field, Some("")).asInstanceOf[Option[String]].get)
          }
        }.toMap

        val sig : String = client.get.fields("id_token_signed_response_alg").asInstanceOf[Option[String]].getOrElse("")
        val alg : String = client.get.fields("id_token_encrypted_response_alg").asInstanceOf[Option[String]].getOrElse("")
        val enc : String = client.get.fields("id_token_encrypted_response_enc").asInstanceOf[Option[String]].getOrElse("")
        val jwksUri : String = client.get.fields("jwks_uri").asInstanceOf[Option[String]].getOrElse("")
        val clientSecret : String = client.get.fields("client_secret").asInstanceOf[Option[String]].getOrElse("")

        val hashAlg = "SHA-" + sig.substring(2)
        val hashBitLen : Int = sig.substring(2).toInt
        val hashLen =  hashBitLen / (8 * 2)
        val md : MessageDigest = MessageDigest.getInstance(hashAlg)
        var codeHash = ""
        if(!codeVal.isEmpty)
          codeHash = Base64URL.encode(md.digest(codeVal.getBytes).slice(0, hashLen)).toString
        var accessTokenHash = ""
        if(!tokenVal.isEmpty)
          accessTokenHash = Base64URL.encode(md.digest(tokenVal.getBytes).slice(0, hashLen)).toString
        val idt = signEncrypt(makeIdToken(wrapUserId(client.get, user.get.login), cid.get, idTokenClaims, nonce, codeHash, accessTokenHash), sig, alg, enc, jwksUri, clientSecret)
        queryString += "id_token" -> Seq(idt )
      }

      if(!state.isEmpty)
        queryString += "state" -> Seq(state)
      val uri = new URI(redirectUri)
      var queryParams = ""
      var fragmentParams = ""
      if(uri.getQuery != null)
        queryParams = uri.getQuery
      if(responseTypes.contains("token") || responseTypes.contains("id_token"))
        fragmentParams = queryString.map{case(x,y) => x + "=" + y.mkString(",")}.mkString("&")
      else {
        if(!queryParams.isEmpty)
          queryParams = queryParams + "&" + queryString.map{case(x,y) => x + "=" + y.mkString(",")}.mkString("&")
        else
          queryParams = queryString.map{case(x,y) => x + "=" + y.mkString(",")}.mkString("&")
      }
      val redirURL = URIUtils.createURI(uri.getScheme, uri.getHost, uri.getPort, uri.getPath, queryParams, fragmentParams)
      Redirect(redirURL.toASCIIString, FOUND)
    }
    catch {
      case e : NoSuchElementException => {Logger.trace("NoSuchElementException" + e); sendError(redirectUri, "invalid_request") }
      case e : OidcException => Logger.trace(e.getStackTraceString); sendError(redirectUri, e.error, e.desc, e.error_uri, state, isQuery)
      //      case unknown => { BadRequest("Unknown error")}
      case e : Throwable => sendError(redirectUri, "unknown_error : " + e, e.getStackTraceString)
    }

  }

  def auth1 = Action { implicit request =>
    try {
      val redirectUri :String = request.getQueryString("redirect_uri").getOrElse("")
//      var res = handleAuth(request)
//      return res
      sendError(redirectUri, "Unknown Error")
      var queryString : Map[String, Seq[String]] = Map()
      var responseTypes : Array[String] = (request.getQueryString("response_type").get).split(' ')
      if(responseTypes.isEmpty)
        throw OidcException("invalid_request", "no response types")
      if(responseTypes.contains("code"))
        queryString += "code" -> Seq("code1")
      if(responseTypes.contains("token"))
        queryString += "token" -> Seq("token1")
      if(responseTypes.contains("id_token"))
        queryString += "token" -> Seq("id_token1")

      queryString += "nonce" -> Seq("noncevalue", "nonceval2")
      Redirect(redirectUri, queryString, FOUND)
    }
    catch {
      case e : NoSuchElementException => { BadRequest("Invalid parameters") }
      case e : OidcException => Logger.trace(e.getStackTraceString); sendError("", "")
      case unknown : Throwable => { BadRequest("Unknown error")}
    }

  }

  def getBearerToken(request : Request[AnyContent]) : String = {

    try {
      val authParts : Array[String] = request.headers.get("authorization").get.split(" ")
      if(authParts(0).compareToIgnoreCase("bearer") != 0)
        throw new Exception("Authorization header does not contain bear token")
      val bearer = authParts(1).trim
      Logger.trace("bearer token : " + bearer)
      bearer
    }
    catch {
      case e : Throwable => Logger.trace("getBearerToken Exception " + e);""
    }
  }


  def isValidAccessToken(token : String) : Boolean = {
    Token.findAccessTokenByName(token) match {
      case None => false
      case _ => true
    }
  }


  def getAccessTokenFromRequest(request : Request[AnyContent]) : String = {
    try {
      var accessToken : String = getBearerToken(request)
      if(accessToken.isEmpty) {
        val postForm : Option[Map[String, Seq[String]]] = request.body.asFormUrlEncoded
        postForm match {
          case None =>  accessToken = request.queryString.getOrElse("access_token", Seq(""))(0)
          case f => accessToken = f.get.getOrElse("access_token", Seq(""))(0)
        }
      }
      if(accessToken.isEmpty)
        throw new Exception("No access token in request")
      accessToken
    }
    catch {
      case e : Throwable => Logger.trace("getAccessTokenFromRequest Exception " + e);""
    }
  }


  def isValidAccessTokenInRequest(request : Request[AnyContent]) : Boolean = {
    try {
      var accessToken : String = getAccessTokenFromRequest(request)
      if(accessToken.isEmpty)
        throw new Exception("access token not found")
      isValidAccessToken(accessToken)
    }
    catch {
      case e : Throwable => Logger.trace("isValidAccessTokenInRequest Exception " + e);false
    }
  }


  def isClientAuthenticated(implicit  request : Request[AnyContent]) : Boolean = {
    val clientAuthForm = Form(
      tuple(
        "client_id" -> optional(text),
        "client_secret" -> optional(text),
        "client_assertion_type" -> optional(text),
        "client_assertion" -> optional(text)
      )
    )


    try {
      Logger.trace("headers = " + request.headers)
      Logger.trace("session = " + request.session.data)

      var (clientId, clientSecret, assertionType, assertion) = clientAuthForm.bindFromRequest.get
      Logger.trace("client_id = " + clientId + " client_secret = " + clientSecret + "\nassertion_type = " + assertionType + " assert = " + assertion)

      var tokenEndpointAuthMethod = "client_secret_basic"
      val dbClient : Option[Client] = (clientId, clientSecret, assertionType, assertion) match {
        case (_, None, None, None) =>  {
          Logger.trace("client_secret_basic matched");
          tokenEndpointAuthMethod = "client_secret_basic"
          val auth : String = request.headers.get("authorization").get
          Logger.trace("auth = " + auth)
          val authParts = auth.split(' ')
          authParts.length match {
            case 2 =>  {
            Logger.trace("parts = " + authParts.toString)
            val authorization = new String(org.apache.commons.codec.binary.Base64.decodeBase64(authParts(1).getBytes(Charset.defaultCharset))).split(':')
            Logger.trace("auth = " + authorization)
            Client.findByClientIdAndClientSecret(authorization(0), authorization(1))
            }
            case _ => None
          }

        }
        case (Some(_), Some(_), None, None) => {
          Logger.trace("client_secret_post matched")
          tokenEndpointAuthMethod = "client_secret_post"
          Client.findByClientIdAndClientSecret(clientId.get, clientSecret.get)
        }
        case (_, None, Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), Some(_)) =>  {
          Logger.trace("client_secret_jwt matched")
          tokenEndpointAuthMethod = "client_secret_jwt"
          val jwsObj : JWSObject = JWSObject.parse(assertion.get)
          val jwsHeader = jwsObj.getHeader
          Logger.trace("jws headers = " + jwsHeader)
          val jwsPayload = jwsObj.getPayload
          Logger.trace("jws payload = " + jwsPayload.toString + " origin = " + jwsPayload.getOrigin)
          val json = jwsPayload.toJSONObject
          json.keySet.toArray.map{case x => Logger.trace(x + " = " + json.get(x))}

          if(json.get("iss").equals(json.get("sub"))) {
            val iat = new DateTime(json.get("iat").asInstanceOf[Long] * 1000)
            val exp = new DateTime(json.get("exp").asInstanceOf[Long] * 1000)
            val now = DateTime.now

            if(iat.isAfterNow)
              Logger.trace("iat is after now")
            if(exp.isBeforeNow)
              Logger.trace("exp is before now")
            val fmt : DateTimeFormatter = DateTimeFormat.forPattern("yyyyMMdd HHmmss z");

            Logger.trace("iat = " + fmt.print(iat) + "\nnow = " + fmt.print(now) + "\nexp = " + fmt.print(exp))
            Client.findByClientId(json.get("iss").asInstanceOf[String])

          }
          else
            None
        }

//        case (_, None, Some("private_key_jwt"), Some(_)) => {
//          Logger.trace("private_key_jwt matched");
//          tokenEndpointAuthMethod = "private_key_jwt"
//          None
//        }
        case _ => Logger.trace("none matched"); None
      }

      Logger.trace("auth method = " + tokenEndpointAuthMethod)

      dbClient match {
        case None => { Logger.trace("no match"); false }
        case c : Option[Client] => {
          tokenEndpointAuthMethod = c.get.fields("token_endpoint_auth_method").asInstanceOf[Option[String]].getOrElse("client_secret_basic")
          tokenEndpointAuthMethod match {
            case "client_secret_jwt" => {
              Logger.trace("in client_secret_jwt")
              val jwsObject : JWSObject = JWSObject.parse(assertion.get)
              val jwsVerifier : JWSVerifier = new MACVerifier(c.get.fields("client_secret").asInstanceOf[Option[String]].get.getBytes)
              jwsObject.verify(jwsVerifier)
            }

            case "private_key_jwt" => {
              Logger.trace("in private_key_jwt")
              val jwsObject : JWSObject = JWSObject.parse(assertion.get)
              val jwsHeader = jwsObject.getHeader
              val jwks : String = getSSLURLContents(c.get.fields("jwks_uri").asInstanceOf[Option[String]].get)
              Logger.trace("jwks = " + jwks)
              val jwkSet = JWKSet.parse(jwks)
              Logger.trace("jwkset = " + jwkSet.toString)
              Logger.trace("jws header = " + jwsHeader.toString)
              val keyId = jwsHeader.getKeyID match {
                case k: String => k
                case _ => ""
              }
              val jwsVerifier : JWSVerifier = new RSASSAVerifier(getJwkRsaSigKey(jwkSet, keyId).get)
              jwsObject.verify(jwsVerifier)
              // val jwsVerifier : JWSVerifier = new RSASSAVerifier()(c.fields("client_secret").asInstanceOf[Option[String]].get.getBytes)
              // jwsObject.verify(jwsVerifier)
            }
            case e : String => Logger.trace("all skipped : method = " + e); true
          }
        }
      }

    }
    catch {
      case e : NoSuchElementException => sendError("", "unauthorized", "no client credentials"); false
      case e : Throwable => Logger.trace("Unknown exception : " + e); false
    }
  }



  def token = Action { implicit request =>
    try {
      if(!isClientAuthenticated )
        throw OidcException("invalid_client", "invalid client credentials")

      val params : Map[String, Seq[String]] = request.body.asFormUrlEncoded.get
      val grantType : String = params.getOrElse("grant_type", Seq(""))(0)
      if(grantType != "authorization_code")
        throw OidcException("invalid_grant_type", "grant type is not authorization_code")
      val code : String = params.getOrElse("code", Seq(""))(0)
      if(code.isEmpty)
        throw OidcException("invalid_authorization_code", "no auth code")

      val dbCode : Option[Token] = Token.findByName(code)
      if(dbCode == None)
        throw OidcException("invalid_authorization_code", "code not found")

      // make access token based on code
      val dbToken : Token = dbCode.get
      dbToken.token = RandomStringUtils.randomAlphanumeric(32)
      dbToken.token_type = Some(1)
      Token.insert(dbToken)
      val jsonReq : JsObject = Json.parse(dbToken.info.get).as[JsObject]
      val account : Account = Account.findById(dbToken.account_id).get
      val client : Client = Client.findByClientId((jsonReq \ "g" \ "client_id").as[String]).get
      val idTokenClaimsList = getIdTokenClaims((jsonReq \ "r").as[JsObject] )
      Logger.trace("idtoken claims = " + idTokenClaimsList)
      val persona = Persona.findByAccountPersona(account, (jsonReq \ "p").asOpt[String].getOrElse("Default")).get
      val allowedClaims : Seq[String] = (jsonReq \ "l").as[Seq[String]]
      val cacheParams : Map[String, Any] = Cache.getAs[Map[String, Any]]("session."+(jsonReq \ "r" \ "sessionid").as[String]).getOrElse(Map())

      Logger.trace("cache param auth_time = " + cacheParams("auth_time").asInstanceOf[DateTime].getMillis + " " + cacheParams("auth_time").asInstanceOf[DateTime])
      val idTokenClaims : Map[String, Any] = idTokenClaimsList.filter(p=> allowedClaims.contains(p)).map{ claimName =>
        claimName match {
          case "phone_number_verified" | "email_verified" => persona.fields.getOrElse(claimName, Some(false)).asInstanceOf[Option[Boolean]].get match {
            case verified : Boolean => (claimName, verified)
          }
          // TODO Add ACR values
//          case "address" => (claimName, new net.minidev.json.JSONObject().put("formatted", persona.fields.getOrElse(claimName, Some("")).asInstanceOf[Option[String]].get))
          case "address" => val addressMap = new java.util.HashMap[String, java.lang.Object]; addressMap.put("formatted", persona.fields.getOrElse(claimName, Some("")).asInstanceOf[Option[String]].get);(claimName, addressMap)
          case "updated_at" => (claimName, persona.fields.getOrElse(claimName, Some(DateTime.now)).asInstanceOf[Option[DateTime]].get)
          case "auth_time" => ("auth_time", cacheParams("auth_time").asInstanceOf[DateTime].getMillis)
          case field : String => (field, persona.fields.getOrElse(field, Some("")).asInstanceOf[Option[String]].get)
        }
      }.toMap

      val sig : String = client.fields("id_token_signed_response_alg").asInstanceOf[Option[String]].getOrElse("")
      val alg : String = client.fields("id_token_encrypted_response_alg").asInstanceOf[Option[String]].getOrElse("")
      val enc : String = client.fields("id_token_encrypted_response_enc").asInstanceOf[Option[String]].getOrElse("")
      val jwksUri : String = client.fields("jwks_uri").asInstanceOf[Option[String]].getOrElse("")
      val clientSecret : String = client.fields("client_secret").asInstanceOf[Option[String]].getOrElse("")

      var codeHash : String = ""
      var accessTokenHash : String = ""
      val idTokenSignAlg : String = client.fields.get("id_token_signed_response_alg").asInstanceOf[Option[Option[String]]].get.getOrElse("RS256")
      if(idTokenSignAlg.compare("none") != 0) {
        val hashAlg = "SHA-" + sig.substring(2)
        val hashBitLen : Int = sig.substring(2).toInt
        val hashLen =  hashBitLen / (8 * 2)
        val md : MessageDigest = MessageDigest.getInstance(hashAlg)
        codeHash = Base64URL.encode(md.digest(code.getBytes).slice(0, hashLen)).toString
        accessTokenHash = Base64URL.encode(md.digest(dbToken.token.getBytes).slice(0, hashLen)).toString
      }

      val jsonResponse = Json.obj(
        "access_token" -> dbToken.token,
        "id_token" -> signEncrypt(makeIdToken(wrapUserId(client, account.login), dbToken.client.get, idTokenClaims,(jsonReq \ "r" \ "nonce").asOpt[String].getOrElse(""), codeHash, accessTokenHash), sig, alg, enc, jwksUri, clientSecret),
        "token_type" -> "bearer",
        "expires_in" -> 3600
      )
      Token.delete(dbCode.get.id)
      Ok(Json.prettyPrint(jsonResponse)).as(JSON).withHeaders(("Cache-Control", "no-store"), ("Pragma","no-cache"))
    }
    catch {
      case e : OidcException => Logger.trace(e.getStackTraceString); sendError("", e.error, e.desc, e.error_uri)
      case e : Throwable => Logger.trace(e.getStackTraceString);sendError("", "invalid_request", "exception: " + e.toString)
    }

  }



  def userinfo = Action { implicit request =>
    Logger.trace("headers = " + request.headers)

    try {
      var accessToken : String = getAccessTokenFromRequest(request)
      if(accessToken.isEmpty)
        throw OidcException("invalid_request", "no access token")
      val optToken : Option[Token] = Token.findAccessTokenByName(accessToken)
      if(optToken == None)
        throw OidcException("invalid_request", "invalid access token")
      val token : Token = optToken.get
      val account : Account = Account.findById(token.account_id).get
      val client : Client = Client.findByClientId(token.client.get).get
      val jsonReq : JsValue = Json.parse(token.info.get)

      val optPersona : Option[Persona] = Persona.findByAccountPersona(account, (jsonReq \ "p").as[String])
      if(optPersona == None)
        throw OidcException("invalid_request", "profile not found")
      val persona : Persona = optPersona.get
      val allowedClaims : Seq[String] = (jsonReq \ "l").as[Seq[String]]
      val requestedUserInfoClaims : Seq[String] = (getUserInfoClaims((jsonReq \ "r").as[JsObject]) ++ List("sub")).asInstanceOf[Seq[String]]
      Logger.trace("userinfo allowed list = " + requestedUserInfoClaims)

      val returnClaims = requestedUserInfoClaims.filter(p => allowedClaims.contains(p)).map(f => f match {
          case "sub"  => (f, Json.toJsFieldJsValueWrapper(wrapUserId(client, account.login)))
          case "phone_number_verified" | "email_verified" => persona.fields.getOrElse(f, Some(false)).asInstanceOf[Option[Boolean]].get match {
                                                            case verified : Boolean => (f, Json.toJsFieldJsValueWrapper(verified))
                                                         }
          case "address" => (f, Json.toJsFieldJsValueWrapper(Json.obj("formatted"->persona.fields.getOrElse(f, Some("")).asInstanceOf[Option[String]].get)))
          case "updated_at" => (f, Json.toJsFieldJsValueWrapper(persona.fields.getOrElse(f, Some(DateTime.now)).asInstanceOf[Option[DateTime]].get))
          case field : String => (field, Json.toJsFieldJsValueWrapper(persona.fields.getOrElse(field, Some("")).asInstanceOf[Option[String]].get))
        }
      )

      Logger.trace("claims = " + returnClaims)
      Logger.trace("claims map = " + returnClaims.toMap)

      val jsonClaims = Json.obj(returnClaims.toSeq:_*)

      val sig : String = client.fields("userinfo_signed_response_alg").asInstanceOf[Option[String]].getOrElse("")
      val alg : String = client.fields("userinfo_encrypted_response_alg").asInstanceOf[Option[String]].getOrElse("")
      val enc : String = client.fields("userinfo_encrypted_response_enc").asInstanceOf[Option[String]].getOrElse("")
      val jwksUri : String = client.fields("jwks_uri").asInstanceOf[Option[String]].getOrElse("")
      val clientSecret : String = client.fields("client_secret").asInstanceOf[Option[String]].getOrElse("")

      Logger.trace("sig: " + sig + " alg: " + alg + " enc: " + enc)

      if(sig.isEmpty & alg.isEmpty)
        Ok(Json.prettyPrint(jsonClaims)).as(JSON)
      else {
        val jwt = signEncrypt(jsonClaims.toString, sig, alg, enc, jwksUri, clientSecret)
        Ok(jwt).as("application/jwt")
      }


    }
    catch {
      case e : OidcException => Logger.trace("userinfo exception " + e + e.getStackTraceString); sendBearerError(e.error, e.desc, UNAUTHORIZED)
      case e : Throwable => Logger.trace("userinfo Exception " + e);sendBearerError("invalid_request", e.toString, UNAUTHORIZED)
    }



//    if(isValidAccessTokenInRequest(request)) {
//      val jsonResponse = Json.obj(
//        "sub" -> "user0837432345574",
//        "name" -> "John A. Doe",
//        "given_name" -> "John",
//        "family_name" -> "Doe",
//        "middle_name" -> "Alphonso",
//        "nickname" -> "Johnny",
//        "preferred_username" -> "john_doe",
//        "profile" -> "http://johndoe.com/john/profile",
//        "picture" -> "https://johndoe.com/john/pic",
//        "website" -> "http://johndoe.com/john",
//        "email" -> "john@johndoe.com",
//        "email_verified" -> true,
//        "gender" -> "M",
//        "birthdate" -> "1990-09-09",
//        "zoneinfo" -> "US/Los Angeles",
//        "locale" -> "en",
//        "phone_number" -> "451-965-5412",
//        "phone_number_verified" -> true,
//        "address" -> Json.obj("formatted" -> "123 Hollywood Blvd., Los Angeles, CA 95120"),
//        "updated_at" -> "2013-03-30 09:00"
//      )
//      Ok(Json.prettyPrint(jsonResponse)).as(JSON)
//    } else
//      BadRequest("no good").as(JSON)

  }

  def getFileContents(file : String) : String = {
    val encoded : Array[Byte] = Files.readAllBytes(Paths.get(file))
    java.nio.charset.Charset.defaultCharset().decode(ByteBuffer.wrap(encoded)).toString

  }

  def getDerRSAPrivateKey(path : String) : PrivateKey = {
    val keyContents : Array[Byte] = FileUtils.readFileToByteArray(new java.io.File(path));
    val keySpec : PKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(keyContents)
    val kf : KeyFactory = KeyFactory.getInstance("RSA")
    kf.generatePrivate(keySpec)
  }

  def getX509PublicKey(path : String) : PublicKey = {
    val fileInput : FileInputStream = new FileInputStream(path)
    val certFactory : CertificateFactory = CertificateFactory.getInstance("X.509")
    val cert : java.security.cert.Certificate =  certFactory.generateCertificate(fileInput)
    cert.getPublicKey
  }

  def getPublicKeyFromCert(certStr:String) : PublicKey = {

    val certFactory : CertificateFactory = CertificateFactory.getInstance("X.509")
    val cert : java.security.cert.Certificate =  certFactory.generateCertificate(new StringBufferInputStream(certStr))
    cert.getPublicKey

  }

  def getURLContents(url : String) : String = {
    Logger.trace("getURLContents : " + url)
    val in : InputStream = new URL(url).openStream();
    try {
      IOUtils.toString(in)
    } finally {
      IOUtils.closeQuietly(in);
    }
  }

  def getSSLURLContents(url : String) : String = {
    Logger.trace("getSSLURLContents : " + url)
    // Create a trust manager that does not validate certificate chains
    val trustAllCerts : Array[TrustManager]  = Array(new X509TrustAllManager)
    // Install the all-trusting trust manager
    val sc : SSLContext = SSLContext.getInstance("SSL");
    sc.init(null, trustAllCerts, new java.security.SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

    // Create all-trusting host name verifier
    val allHostsValid : HostnameVerifier = new AllHostnameVerifier

    // Install the all-trusting host verifier
    HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

    val in : InputStream = new URL(url).openStream();
    try {
      IOUtils.toString(in)
    } finally {
      IOUtils.closeQuietly(in);
    }
  }


  def getOpPrivateKey() : PrivateKey = {
    getDerRSAPrivateKey(Play.application.configuration.getString("op.privateKey").get)
  }

  def getConfig(key : String) : String = {
    Play.application.configuration.getString(key).get
  }


  def encrypt(plainText : Array[Byte]) : Array[Byte] =
  {
    try
    {
      val key : Array[Byte] = Array(10, 22, 35, 56, 78, 93, -33, -100, 123, 88, 60, 95, 42, 39, 2, -99).map{x => x.toByte}
      val iv : Array[Byte] = Array(0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8).map{x => x.toByte}
      val cipher : Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      val secretKey : SecretKeySpec = new SecretKeySpec(key, "AES")
      val ivSpec : IvParameterSpec = new IvParameterSpec(iv)
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
      cipher.doFinal(plainText)
    }
    catch {
      case e : Throwable => print("encrypt error " + e + "\n" + e.getStackTraceString);null
    }
  }

  def decrypt(cipherText : Array[Byte]) : Array[Byte] =
  {
    try
    {
      val key : Array[Byte] = Array(10, 22, 35, 56, 78, 93, -33, -100, 123, 88, 60, 95, 42, 39, 2, -99).map{x => x.toByte}
      val iv : Array[Byte] = Array(0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8).map{x => x.toByte}
      val cipher : Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      val secretKey : SecretKeySpec = new SecretKeySpec(key, "AES")
      val ivSpec : IvParameterSpec = new IvParameterSpec(iv)
      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
      cipher.doFinal(cipherText)
    }
    catch {
      case e : Throwable => print("decrypt error " + e + "\n" + e.getStackTraceString);null
    }
  }

  def deflate(data : Array[Byte]) : Array[Byte] = {
    val deflater : Deflater = new Deflater(Deflater.DEFAULT_COMPRESSION,true)
    deflater.setInput(data)

    val outputStream : ByteArrayOutputStream  = new ByteArrayOutputStream(data.length);

    deflater.finish()
    val buffer : Array[Byte] = new Array(1024)
    while (!deflater.finished()) {
      val count = deflater.deflate(buffer)
      outputStream.write(buffer, 0, count)
    }
    outputStream.close()
    outputStream.toByteArray
  }

  def inflate(data : Array[Byte]) : Array[Byte] = {
    val inflater : Inflater  = new Inflater(true)
    inflater.setInput(data)

    val outputStream : ByteArrayOutputStream  = new ByteArrayOutputStream(data.length)
    val buffer : Array[Byte]  = new Array(1024)
    while (!inflater.finished()) {
      val count = inflater.inflate(buffer)
      outputStream.write(buffer, 0, count)
    }
    outputStream.close()
    outputStream.toByteArray
  }


  def wrapUserId(client : Client, userid : String) : String = {
    val clientId : String = client.fields.get("client_id").asInstanceOf[Option[Option[String]]].get.get
    val subjectType : String = client.fields.get("subject_type").asInstanceOf[Option[Option[String]]].get.getOrElse("pairwise")
    subjectType match {
      case "public" => userid
      case _ => { // pairwise
        val inputString : String = clientId + ":" + userid
        var wrappedId = new String(org.apache.commons.codec.binary.Hex.encodeHex(encrypt(deflate(inputString.getBytes("UTF-8")))))
        Logger.trace("inputString = " + inputString + " wrapped = " + wrappedId)
        wrappedId
      }
    }
  }

  def unWrapUserId(wrappedUserId : String) : String = {

    try {
      val acct : Option[Account] = Account.findByLogin(wrappedUserId)
      acct match {
        case Some(_) => {
          Logger.trace("already unwrapped Id = " + wrappedUserId)
          wrappedUserId  // userId is already unwrapped
        }
        case None => {
          var chars : Array[Char] = new Array(wrappedUserId.length)
          wrappedUserId.getChars(0,wrappedUserId.length, chars, 0)
          Logger.trace("char " + new String(chars))
//          Logger.trace("hex = " + new String(Hex.decodeHex(chars)))
          var unwrappedId = new String(inflate(decrypt(Hex.decodeHex(chars))))
          Logger.trace("unwrappedId =  " + unwrappedId)
          val name = unwrappedId.split(':')(1)
          Logger.trace("name = " + name)
          name
        }
      }
    }
    catch {
      case e : Throwable => Logger.trace("unwrap exception = " + e + e.getStackTraceString);""
    }
  }

  def makeIdToken(sub : String, client : String, claims : Map[String, Any] = Map(), nonce : String = "", codeHash : String = "", accessTokenHash: String = "") : String = {

    var jwtClaims : JWTClaimsSet  = new JWTClaimsSet()
    jwtClaims.setIssuer(getConfig("op.issuer"))
    jwtClaims.setSubject(sub)
    var aud : java.util.List[String]  = new util.ArrayList[String]
    aud.add(client)
    jwtClaims.setAudience(aud)
    // Set expiration in 10 minutes
    jwtClaims.setExpirationTime(new java.util.Date(new java.util.Date().getTime + 1000*60*10))
    jwtClaims.setNotBeforeTime(new java.util.Date())
    jwtClaims.setIssueTime(new java.util.Date())
    jwtClaims.setJWTID(java.util.UUID.randomUUID().toString)
    claims.foreach{ case (key, value) => Logger.trace("idtoken claim : " + key + " = " + value);jwtClaims.setCustomClaim(key, value)}


    if(!codeHash.isEmpty)
      jwtClaims.setCustomClaim("c_hash", codeHash)
    if(!accessTokenHash.isEmpty)
      jwtClaims.setCustomClaim("at_hash", accessTokenHash)

    if(!nonce.isEmpty)
      jwtClaims.setCustomClaim("nonce", nonce)
    Logger.trace("idtoken string = " + jwtClaims.toJSONObject.toJSONString)
    jwtClaims.toJSONObject.toJSONString
  }

  def getJWE(alg : String, enc : String, jwksUri : String, payload:String) : String = {
    var jwe : String = ""
    if(!alg.isEmpty && !enc.isEmpty && !jwksUri.isEmpty && !payload.isEmpty) {
      val jwks : String = getSSLURLContents(jwksUri)
      val jwkSet = JWKSet.parse(jwks)

      val enckeys : Array[JWK] = getJwkKeys(jwkSet, KeyType.RSA, "enc")
      if(!enckeys.isEmpty) {
        val jweAlg = JWEAlgorithm.parse(alg)
        val jweEnc = EncryptionMethod.parse(enc)
        val jweHeader = new JWEHeader(jweAlg, jweEnc)

        val rsaKey : RSAPublicKey = enckeys(0).asInstanceOf[RSAKey].toRSAPublicKey
        if(enckeys(0).getKeyID != null)
          jweHeader.setKeyID(enckeys(0).getKeyID)
        val jweEncrypter : JWEEncrypter = new RSAEncrypter(rsaKey)
        val jweObject : JWEObject = new JWEObject(jweHeader, new jose.Payload(payload))
        jweObject.encrypt(jweEncrypter)
        jwe = jweObject.serialize()
      }
    }
    Logger.trace("jwe returning " + jwe)
    jwe
  }


  def getJWS(alg : String, payloadStr : String, macSecret : String = "") : String = {
    var jws : String = ""
    var jwsAlg : JWSAlgorithm = new JWSAlgorithm(alg)
    val privKey : RSAPrivateKey = getOpPrivateKey.asInstanceOf[RSAPrivateKey]
    var jwsSigner : JWSSigner = null
    alg.substring(0, 2) match {
      case "HS" => jwsSigner  = new MACSigner(macSecret.getBytes)
      case "RS" => jwsSigner  = new RSASSASigner(privKey)
      case _ =>
    }

    val payload = new PayloadExtStr(payloadStr)
    if(jwsSigner != null) {
      val header = new JWSHeader(jwsAlg)
      //    header.setKeyID("key00")
      val jwsObject = new JWSObject(header, payload)
      jwsObject.sign(jwsSigner)
      jws = jwsObject.serialize()
    } else {

      val header = new PlainHeader()
      val jwtPlain : PlainJWT = new PlainJWT(header.toBase64URL, Base64URL.encode(payloadStr))
      jws = jwtPlain.serialize()
    }

    Logger.trace("JWS signature = " + jws)
    jws
  }

  def verifyJWS(jws : String, sig : String, secret : String, jwkSet : JWKSet) : Boolean = {
    var verified : Boolean = false
    try {
      val joseObject: JOSEObject = JOSEObject.parse(jws)
      val joseHeader: ReadOnlyHeader = joseObject.getHeader
      if (joseObject.isInstanceOf[JWSObject]) {
        val jws: JWSObject = joseObject.asInstanceOf[JWSObject]
        val jwsHeader: JWSHeader = joseHeader.asInstanceOf[JWSHeader]
        val jwsAlg: JWSAlgorithm = JWSAlgorithm.parse(sig)
        if(sig.length > 0) {
          Logger.trace("Alg  = " + jwsAlg.toString + " : " + sig)
          if(!jwsHeader.getAlgorithm.equals(jwsAlg))
            throw new Exception("Signature Algorithm different from registered Alg")
        }

        val headerAlg = jwsHeader.getAlgorithm.getName
        Logger.trace("header alg = " + headerAlg)

        val jwsVerifier = headerAlg.substring(0, 2) match {
          case "HS" => new MACVerifier(secret.getBytes)
          case "RS" => {
            val keyId = jwsHeader.getKeyID match {
              case k: String => k
              case _ => ""
            }
            new RSASSAVerifier(getJwkRsaSigKey(jwkSet, keyId).get)
          }
        }
        verified = jws.verify(jwsVerifier)
      }
    }
    catch {
      case e : Throwable => Logger.trace("verifyJWS exception + " + e + "\n" + e.getStackTraceString)
    }
    Logger.trace("JWS verified = " + verified)
    verified
  }

  def decryptJWE(jwt : String) : String = {
    var decryptedPayload = ""
    try {
      val joseObject: JOSEObject = JOSEObject.parse(jwt)
      val joseHeader: ReadOnlyHeader = joseObject.getHeader
      if (joseObject.isInstanceOf[JWEObject]) {
        val jwe: JWEObject = joseObject.asInstanceOf[JWEObject]
        val jweHeader: JWEHeader = joseHeader.asInstanceOf[JWEHeader]
        val jweDecrypter: JWEDecrypter = new RSADecrypter(getOpPrivateKey.asInstanceOf[RSAPrivateKey])
        jwe.decrypt(jweDecrypter)
        val payload : jose.Payload = jwe.getPayload
        if(payload != null)
          decryptedPayload = payload.toString
      }
    }
    catch {
      case e : Throwable => Logger.trace("decryptJWE exception + " + e + "\n" + e.getStackTraceString)
    }
    Logger.trace("Decrypted Payload = " + decryptedPayload)
    decryptedPayload
  }

  def signEncrypt(payload : String, sig : String, alg : String, enc : String, jwksUri : String, clientSecret : String) : String = {
    var jwt : String = payload
    if(!sig.isEmpty)
      jwt = getJWS(sig, payload, clientSecret)
    if(!alg.isEmpty && !enc.isEmpty && !jwksUri.isEmpty)
      jwt = getJWE(alg, enc, jwksUri, jwt)
    jwt
  }

  def decryptVerify(jwt : String) = {
    val joseObj : JOSEObject = JOSEObject.parse(jwt)

  }

  def dbTest = Action { implicit request =>
    val ubuntu : String = getSSLURLContents("https://ubuntu/abrp/index.php/sector_id");
    Logger.trace("ubuntu = " + ubuntu)
    val phprp : String = getSSLURLContents("https://phprp.sonicdemo.local/abrp/index.php/sector_id");
    Logger.trace("phprp = " + phprp)
    Ok(ubuntu + "\n" + phprp).as(TEXT)
  }


  def dbTest1 = Action { implicit request =>
    try {
      DB.withConnection { implicit conn =>
//        val result : Boolean  = accountSQL.on("login" -> "alice").execute()
//        val accountSQL = SQL("select * from accounts a where a.login = {login}")
//        val result: List[(((Int, String), String), Int)] = (accountSQL.on("login" -> "alice"))().map(row => row[Int]("id") -> row[String]("login") -> row[String]("crypted_password") -> row[Int]("enabled")).toList

        val result = Account.list()
        Logger.trace("List = " + result)

        val acct1 : Option[Account] = Account.authenticate("alice", "hello")



        Logger.trace("account = " + acct1)
        if(acct1 == None)
          Logger.trace("account not found")

//        var pay1 : Payload = Payload.apply("hello")

        // Create JWS payload
        var payload : PayloadExtStr = new PayloadExtStr("Hello world!")


        // Create JWS header with HS256 algorithm
        var header : JWSHeader = new JWSHeader(JWSAlgorithm.HS256)
        header.setContentType("text/plain")

        // Create JWS object
        var jwsObject : JWSObject  = new JWSObject(header, payload)

        // Create HMAC signer
        var sharedKey : String = "a0a2abd8-6162-41c3-83d6-1cf559b46afc"

        var signer : JWSSigner = new MACSigner(sharedKey.getBytes)
        jwsObject.sign(signer)

        // Serialise JWS object to compact format
        var s : String = jwsObject.serialize()
        System.out.println("Serialised JWS object: " + s)


        val path : String = "/home/edmund/work/oidcop/keys/2048DER.pkcs8"
        var privKeyPEM : String = getFileContents(path)

        privKeyPEM = privKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "")
        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "")
        Logger.trace("privkeyPem = " + privKeyPEM)

        val ek : Array[Byte] = org.apache.commons.io.FileUtils.readFileToByteArray(new java.io.File(path));

        // val encodedKey : Array[Byte] = org.apache.commons.codec.binary.Base64.decodeBase64(privKeyPEM)

        val keySpec : PKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(ek)
        val kf : KeyFactory = KeyFactory.getInstance("RSA")
        val privKey : PrivateKey = kf.generatePrivate(keySpec)

        Logger.trace("privateKey " + privKey.toString)


        var pubKeyPEM = getFileContents("/home/edmund/work/oidcop/keys/2048.pub")
        pubKeyPEM = pubKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "")
        pubKeyPEM = pubKeyPEM.replace("-----END PUBLIC KEY-----", "")

        val decodedPub : Array[Byte] = org.apache.commons.codec.binary.Base64.decodeBase64(pubKeyPEM.getBytes)
        val x509 : X509EncodedKeySpec = new X509EncodedKeySpec(decodedPub)
        val pubKey : PublicKey = kf.generatePublic(x509)

        Logger.trace("publicKey " + pubKey.toString)

        val pubCert = getFileContents("/home/edmund/work/oidcop/keys/2048.crt")
        val fileInput : FileInputStream = new FileInputStream("/home/edmund/work/oidcop/keys/2048.crt")
        val certFactory : CertificateFactory = CertificateFactory.getInstance("X.509")
        val cert : java.security.cert.Certificate =  certFactory.generateCertificate(fileInput)

        val pk  = cert.getPublicKey
        Logger.trace("cert publicKey " + pk.toString)

        // Compose the JWT claims set
        var jwtClaims : JWTClaimsSet  = new JWTClaimsSet()
        jwtClaims.setIssuer("https://openid.net")
        jwtClaims.setSubject("alice")
        var aud : java.util.List[String]  = new util.ArrayList[String]
        aud.add("https://app-one.com")
        aud.add("https://app-two.com")
        jwtClaims.setAudience(aud)
        // Set expiration in 10 minutes
        jwtClaims.setExpirationTime(new java.util.Date(new java.util.Date().getTime + 1000*60*10))
        jwtClaims.setNotBeforeTime(new java.util.Date())
        jwtClaims.setIssueTime(new java.util.Date())
        jwtClaims.setJWTID(java.util.UUID.randomUUID().toString)

        Logger.trace(jwtClaims.toJSONObject.toString)
        // Produces
        // {
        //   "iss" : "https:\/\/openid.net",
        //   "sub" : "alice",
        //   "aud" : [ "https:\/\/app-one.com" , "https:\/\/app-two.com" ],
        //   "exp" : 1364293137871,
        //   "nbf" : 1364292537871,
        //   "iat" : 1364292537871,
        //   "jti" : "165a7bab-de06-4695-a2dd-9d8d6b40e443"
        // }

        // Request JWT encrypted with RSA-OAEP and 128-bit AES/GCM
        val jweHeader : JWEHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM)

        // Create the encrypted JWT object
        val jwt : EncryptedJWT  = new EncryptedJWT(jweHeader, jwtClaims)

        // Create an encrypter with the specified public RSA key
        val encrypter : RSAEncrypter  = new RSAEncrypter(pubKey.asInstanceOf[RSAPublicKey])

        // Do the actual encryption
        jwt.encrypt(encrypter)

        // Serialise to JWT compact form
        val jwtString : String = jwt.serialize()

        Logger.trace(jwtString)
        // Produces
        //
        // eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.K52jFwAQJH-
        // DxMhtaq7sg5tMuot_mT5dm1DR_01wj6ZUQQhJFO02vPI44W5nDjC5C_v4p
        // W1UiJa3cwb5y2Rd9kSvb0ZxAqGX9c4Z4zouRU57729ML3V05UArUhck9Zv
        // ssfkDW1VclingL8LfagRUs2z95UkwhiZyaKpmrgqpKX8azQFGNLBvEjXnx
        // -xoDFZIYwHOno290HOpig3aUsDxhsioweiXbeLXxLeRsivaLwUWRUZfHRC
        // _HGAo8KSF4gQZmeJtRgai5mz6qgbVkg7jPQyZFtM5_ul0UKHE2y0AtWm8I
        // zDE_rbAV14OCRZJ6n38X5urVFFE5sdphdGsNlA.gjI_RIFWZXJwaO9R.oa
        // E5a-z0N1MW9FBkhKeKeFa5e7hxVXOuANZsNmBYYT8G_xlXkMD0nz4fIaGt
        // uWd3t9Xp-kufvvfD-xOnAs2SBX_Y1kYGPto4mibBjIrXQEjDsKyKwndxzr
        // utN9csmFwqWhx1sLHMpJkgsnfLTi9yWBPKH5Krx23IhoDGoSfqOquuhxn0
        // y0WkuqH1R3z-fluUs6sxx9qx6NFVS1NRQ-LVn9sWT5yx8m9AQ_ng8MBWz2
        // BfBTV0tjliV74ogNDikNXTAkD9rsWFV0IX4IpA.sOLijuVySaKI-FYUaBy
        // wpg


        // Parse back
        val jwt1 = EncryptedJWT.parse(jwtString)

        // Create a decrypter with the specified private RSA key
        val decrypter : RSADecrypter  = new RSADecrypter(privKey.asInstanceOf[RSAPrivateKey])

        // Decrypt
        jwt.decrypt(decrypter)

        // Retrieve JWT claims
        Logger.trace(jwt.getJWTClaimsSet.getIssuer)
        Logger.trace(jwt.getJWTClaimsSet.getSubject)
        Logger.trace(jwt.getJWTClaimsSet.getAudience.toString)
        Logger.trace(jwt.getJWTClaimsSet.getExpirationTime.toString)
        Logger.trace(jwt.getJWTClaimsSet.getNotBeforeTime.toString)
        Logger.trace(jwt.getJWTClaimsSet.getIssueTime.toString)
        Logger.trace(jwt.getJWTClaimsSet.getJWTID)
        Logger.trace("is rsapublic " + pubKey.isInstanceOf[RSAPublicKey])
        Logger.trace("is public " + pubKey.isInstanceOf[PublicKey])
        Logger.trace("is private " + privKey.isInstanceOf[PrivateKey])
        Logger.trace("is rsaprivate " + privKey.isInstanceOf[RSAPrivateKey])
        Logger.trace("is private " + pubKey.isInstanceOf[RSAPrivateKey])

        val rsaSigner : RSASSASigner = new RSASSASigner(privKey.asInstanceOf[RSAPrivateKey])
        var rsaVerifier : RSASSAVerifier = new RSASSAVerifier(pubKey.asInstanceOf[RSAPublicKey])

        var rsaHeader : JWSHeader = new JWSHeader(JWSAlgorithm.RS256)
        rsaHeader.setContentType("text/plain")

        var rsaObject : JWSObject  = new JWSObject(rsaHeader, payload)
        rsaObject.sign(rsaSigner)
        val sig : String = rsaObject.serialize()
        Logger.trace("rsa sig = " + sig)

        val parts : Array[String] = sig.split("\\.")
        Logger.trace("parts = " + parts.toString)
        parts.foreach( e => Logger.trace("elem = " + e))
        val rsaJwsObject : JWSObject = new JWSObject(new Base64URL(parts(0)), new Base64URL(parts(1)), new Base64URL(parts(2)))
        Logger.trace("rsa sig = " + rsaJwsObject.verify(rsaVerifier))

        Logger.trace("private key = " + Play.application.configuration.getString("op.privateKey").get)
        Logger.trace("public Cert = " + Play.application.configuration.getString("op.publicCert").get)

        val idtoken : String = makeIdToken("alice", "client_id_00")
        Logger.trace("id token = " + idtoken)
        val jws = getJWS("RS256", idtoken)
        Logger.trace("signed idtoken = " + jws)

        // Logger.trace("URL of http://www.google.com = " + getURLContents("http://www.google.com"))

        // System.out.println(Client.list)
        val cli =  Client.findByClientId("TymRHzVT1kafXk0_rF7lIw").get
        val cf = cli.fields
        Logger.trace("cf client_id = " + cf("client_id") + "\nclient_secret " +cf("client_secret"))
        cli.fields("default_acr_values") = Some("acr11, acr22, acr33")
//        Client.update(cf("id").asInstanceOf[Some[Long]].get, cli)
        Client.update(cli)
        cli.fields("client_id") = Some("newclid")
        Client.insert(cli)

        Logger.trace("client update = " + Client.paramsToUpdate(Client.toParams(cli)))
        Logger.trace("client insert = " + Client.paramsToInsert(Client.toParams(cli)))

//        Logger.trace("client = " + cf)
//        Logger.trace("filtered client = " + cf.filter(x => x._2 != None))
//          Logger.trace("clients = " + Client.list())
//          Logger.trace("personas = " + Persona.list())


        val account : Account = Account.findByLogin("alice").get
        val persona : Persona = Persona.findByAccountPersona(account, "Default").get

        Logger.trace("alice's persona = " + persona)
        persona.fields("name") = "alice test"
        Logger.trace(persona.fields("name").toString)

        var token : Token = Token.findByName("xKCbVab88_yecbmilJLZhL0XjjKgc03glFKDX5bLQOE").get

        token.expiration_at = Some(DateTime.now().plusMinutes(30))
        token.issued_at = Some(DateTime.now())

        Token.update(token)

        token.token = "newtoken1"
        Token.insert(token)


        Logger.trace("token = " + token)

        val md : MessageDigest = MessageDigest.getInstance("SHA-1")
//        val acct2 = Account(0, "Bugs Bunny", new String(Hex.encodeHex(md.digest("passowrd".getBytes(Charset.defaultCharset)))), 1, NormalUser)
        val acct2 = Account(0, "Bugs Bunny", DigestUtils.shaHex("password"), 1, NormalUser)
        Account.insert(acct2)


        val testList = List("one", "two", "three")
        testList.foreach( attrib => Logger.trace("attrib = " + attrib))
        testList.foreach({attrib => print(attrib)})
        val attseq : Seq[JsValue] = testList.map(value => JsString(value)).toSeq

        Logger.trace("Seq = " + attseq)

        val testMap1 = Map("p1" -> "one", "p2" -> "two", "p3" -> "three")

        Logger.trace("map1 = " + testMap1)

        testMap1.foreach({case (x:String, y:String) => println(x + " = " + y )})

        val testMap2 = Map("c1" -> "one", "c2" -> "two", "c3" -> "three")

        Logger.trace("map2 = " + testMap2)

        testMap2.foreach({case (x:String, y:String) => println(x + " = " + y )})


        val tok = Token.create_token_info("t1name", "Default", testList, testMap1, testMap2)

        Logger.trace("query = " + request.queryString)

        val newq = request.queryString.map({case(x,y:Seq[String]) => x-> y.mkString(",")})
        Logger.trace("new1 = " + newq)

        request.session +("k1", "p1")

        Logger.trace("session = " +  request.session)

        session

        val site : Option[TrustedSite] = TrustedSite.findByAccountPersonaClient("alice", "default", "felK84-O6rz7jmSu-X8jaQ")

        Ok(result.toString() + "\n" + tok + site.toString).withSession(session + ("k1"->"p1"))





      }

    }
    catch {
      case unknown : Throwable => { BadRequest(unknown.toString)}
    }
  }


  def getJwkKeys(jwkSet : JWKSet, kty : KeyType, use : String = "", kid : String = "") : Array[JWK] = {
    var jwkList : Array[JWK] =  jwkSet.getKeys.toArray( new Array[JWK](jwkSet.getKeys.size))
    jwkList = jwkList.filter(jwk => jwk.getKeyType.equals(kty))
    val unspecifiedKeys = jwkList.filter(jwk => jwk.getKeyUse == null)
    val sigKeys = jwkList.filter(jwk=> if(jwk.getKeyUse != null) jwk.getKeyUse.equals(Use.SIGNATURE) else false)
    val encKeys = jwkList.filter(jwk=> if(jwk.getKeyUse != null) jwk.getKeyUse.equals(Use.ENCRYPTION) else false)

    Logger.trace("unspecified keys = " + unspecifiedKeys)
    unspecifiedKeys.foreach{k => Logger.trace(k.toJSONString)}
    Logger.trace("sig keys = " + sigKeys)
    sigKeys.foreach{k => Logger.trace(k.toJSONString)}
    Logger.trace("enc keys = " + encKeys)
    encKeys.foreach{k => Logger.trace(k.toJSONString)}


    if(!use.isEmpty) {
      jwkList = use match {
      case "sig" => sigKeys ++ unspecifiedKeys
      case "enc" => encKeys ++ unspecifiedKeys
      }
    }

    if(!kid.isEmpty){
      jwkList = jwkList.filter(jwk => {
        if(jwk.getKeyID != null)
          jwk.getKeyID.equals(kid)
        else false
      })
    }
    jwkList
  }

  def getJwkRsaSigKey(jwkSet : JWKSet, kid : String = "") : Option[RSAPublicKey] = {
    val keys : Array[JWK] = getJwkKeys(jwkSet, KeyType.RSA, "sig", kid)
    Logger.trace("RSA sig keys = " + keys)
    keys.foreach{k => Logger.trace(k.toJSONString)}
    if(keys.isEmpty)
      None
    else
      Some(keys(0).asInstanceOf[RSAKey].toRSAPublicKey)
  }


  def checksession = Action { implicit request =>
    Ok(views.html.checksession())
  }


  def endsession = Action { implicit request =>
    Application.gotoLogoutSucceeded(request)
  }

  def getJwkRsaEncKey(jwkSet : JWKSet, kid : String = "") : Option[RSAPublicKey] = {
    val keys : Array[JWK] = getJwkKeys(jwkSet, KeyType.RSA, "enc", kid)
    Logger.trace("RSA enc keys = " + keys)
    keys.foreach{k => Logger.trace(k.toJSONString)}
    if(keys.isEmpty)
      None
    else
      Some(keys(0).asInstanceOf[RSAKey].toRSAPublicKey)
  }

  def jwkTest = Action { implicit request =>

    try {

      val opPrivatekey : RSAPrivateCrtKey = getDerRSAPrivateKey("/home/edmund/work/abop/testkeys/speckeys/op_private.pkcs8").asInstanceOf[RSAPrivateCrtKey]
      val opPublicKey : RSAPublicKey = getX509PublicKey("/home/edmund/work/abop/testkeys/speckeys/op_public_cert.pem").asInstanceOf[RSAPublicKey]

      val rpPrivatekey : RSAPrivateCrtKey = getDerRSAPrivateKey("/home/edmund/work/abop/testkeys/speckeys/rp_private.pkcs8").asInstanceOf[RSAPrivateCrtKey]
      val rpPublicKey : RSAPublicKey = getX509PublicKey("/home/edmund/work/abop/testkeys/speckeys/rp_public_cert.pem").asInstanceOf[RSAPublicKey]

//      val rsaMulti : RSAMultiPrimePrivateCrtKey = null

//      val rsaMultiPrimePrivateCrtKeySpec : RSAMultiPrimePrivateCrtKeySpec = new RSAMultiPrimePrivateCrtKeySpec(opPrivatekey.getModulus, opPrivatekey.get)

      val rsaOPKey = new RSAKey(opPublicKey, opPrivatekey.asInstanceOf[RSAPrivateCrtKey], null, null, null,null, null, null)
      val rsaRPKey = new RSAKey(rpPublicKey, rpPrivatekey.asInstanceOf[RSAPrivateCrtKey], null, null, null,null, null, null)

      val jwkString = "OP JWK :\n" + rsaOPKey.toJSONString + "\nRP JWK :\n" + rsaRPKey.toJSONString
      Logger.trace(jwkString)

      var payloadStr : String = "ew0KICJpc3MiOiAiczZCaGRSa3F0MyIsDQogImF1ZCI6ICJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsDQogInJlc3BvbnNlX3R5cGUiOiAiY29kZSBpZF90b2tlbiIsDQogImNsaWVudF9pZCI6ICJzNkJoZFJrcXQzIiwNCiAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vY2xpZW50LmV4YW1wbGUub3JnL2NiIiwNCiAic2NvcGUiOiAib3BlbmlkIiwNCiAic3RhdGUiOiAiYWYwaWZqc2xka2oiLA0KICJub25jZSI6ICJuLTBTNl9XekEyTWoiLA0KICJtYXhfYWdlIjogODY0MDAsDQogImNsYWltcyI6IA0KICB7DQogICAidXNlcmluZm8iOiANCiAgICB7DQogICAgICJnaXZlbl9uYW1lIjogeyJlc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgIm5pY2tuYW1lIjogbnVsbCwNCiAgICAgImVtYWlsIjogeyJlc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgImVtYWlsX3ZlcmlmaWVkIjogeyJlc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgInBpY3R1cmUiOiBudWxsDQogICAgfSwNCiAgICJpZF90b2tlbiI6IA0KICAgIHsNCiAgICAgImdlbmRlciI6IG51bGwsDQogICAgICJiaXJ0aGRhdGUiOiB7ImVzc2VudGlhbCI6IHRydWV9LA0KICAgICAiYWNyIjogeyJ2YWx1ZXMiOiBbInVybjptYWNlOmluY29tbW9uOmlhcDpzaWx2ZXIiXX0NCiAgICB9DQogIH0NCn0"
      var alg : String = "RS256"
      var jws : String = ""
      var jwsAlg : JWSAlgorithm = new JWSAlgorithm(alg)
      val privKey : RSAPrivateKey = rpPrivatekey.asInstanceOf[RSAPrivateKey]
      var jwsSigner : JWSSigner = null
      alg.substring(0, 2) match {
        case "RS" => jwsSigner  = new RSASSASigner(privKey)
        case _ =>
      }

      val payload = new PayloadExtBase64Url(new Base64URL(payloadStr))
      if(jwsSigner != null) {
        val header = new JWSHeader(jwsAlg)
        //    header.setKeyID("key00")
        val jwsObject = new JWSObject(header, payload)
        jwsObject.sign(jwsSigner)
        jws = jwsObject.serialize()
      } else {

        val header = new PlainHeader()
        val jwtPlain : PlainJWT = new PlainJWT(header.toBase64URL, Base64URL.encode(payloadStr))
        jws = jwtPlain.serialize()
      }

      Logger.trace("JWS signature = " + jws)
      jws



      if(false) {
        val jwk = getFileContents("/home/edmund/work/oidcop/public/keys/jwktest.jwk")
        Logger.trace("jwk = " + jwk)

        val jwkSet : JWKSet = JWKSet.parse(jwk)
        val keyList : java.util.List[JWK] = jwkSet.getKeys()
        val it : java.util.Iterator[JWK] = keyList.iterator()
        while(it.hasNext){
          val jwkKey : JWK = it.next()
          Logger.trace("jwk key = " + jwkKey.toJSONString)
          if(jwkKey.getAlgorithm != null)
            Logger.trace("alg = " + jwkKey.getAlgorithm.toString + "\n")
          if(jwkKey.getKeyID != null)
            Logger.trace("keyId" + jwkKey.getKeyID + "\n" )
          if(jwkKey.getKeyType != null)
            Logger.trace("type" + jwkKey.getKeyType.toString + "\n" )
          if(jwkKey.getKeyUse != null)
            Logger.trace("use" + jwkKey.getKeyUse.name() + "\n" )
          Logger.trace("key" + jwkKey.asInstanceOf[RSAKey].toRSAPublicKey.toString + "\n")
          //          "keyId" + jwkKey.getKeyID + "\n" +
          //          "keyId" + jwkKey.getKeyID + "\n" +
          //          "keyId" + jwkKey.getKeyID + "\n"
        }

        Logger.trace("key")

        val sigKey = getJwkRsaSigKey(jwkSet)
        Logger.trace("############sig keys = " + sigKey)

        val sigKey1 = getJwkRsaSigKey(jwkSet, "key03")
        Logger.trace("############sig keys 1= " + sigKey1)

        val encKey1 = getJwkRsaEncKey(jwkSet, "key03")
        Logger.trace("############enc keys 1= " + encKey1)

        val encKey2 = getJwkRsaEncKey(jwkSet, "key04")
        Logger.trace("############enc keys 2 = " + encKey2)
      }



      Ok(jwkString + "\n" + jws).as(TEXT)
    }
    catch {
      case e : Throwable => {BadRequest(e.toString + "\n" + e.getStackTraceString)}
    }
  }

}