package controllers

import play.api._
import play.api.mvc._
import play.api.libs.json._
import anorm._
import play.api.db._
import play.api.Play.current
import play.api.data.Forms._
import play.api.data._
import models._
import com.nimbusds.jose._
import com.nimbusds.jose.crypto._
import com.nimbusds.jose.jwk._
import com.nimbusds.jose.util._
import com.nimbusds.jwt._
import javax.validation.Payload
import java.nio.file.{Files, Paths}
import java.nio.charset.Charset
import java.nio.ByteBuffer
import java.security.spec.{X509EncodedKeySpec, PKCS8EncodedKeySpec, RSAMultiPrimePrivateCrtKeySpec}
import java.security._
import java.security.interfaces.{RSAMultiPrimePrivateCrtKey, RSAPrivateCrtKey}
import javax.net.ssl.{HostnameVerifier, HttpsURLConnection, SSLContext, SSLSession, TrustManager, X509TrustManager}

import java.io._
import java.security.cert.CertificateFactory
import java.util
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import org.apache.commons.io.{FileUtils, IOUtils}
import org.apache.http.client.utils._
import java.net.URL
import org.apache.commons.codec.binary.Hex
import org.apache.commons.codec.digest.DigestUtils
import org.joda.time.DateTime
import org.joda.time.format.{DateTimeFormatter, DateTimeFormat}
import jp.t2v.lab.play2.auth._
import jp.t2v.lab.play2.stackc.{RequestWithAttributes, RequestAttributeKey, StackableController}
import scala.sys.process.ProcessBuilder.URLBuilder
import scala.sys.process
import org.apache.commons.lang3.RandomStringUtils
import java.sql.Timestamp
import utils._


/**
 * Created with IntelliJ IDEA.
 * User: Edmund
 * Date: 4/23/13
 * Time: 2:53 PM
 * To change this template use File | Settings | File Templates.
 */

case class OidcException(error : String, desc : String = "", error_uri : String = ""  ) extends Throwable {
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
                                      "issuer" -> issuerPath,
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
                                      "updated_time"
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
//      Ok("Got request [" + request + "]\n" +
//         "query = [" + request.queryString + "]\n" +
//         "host = [" + request.host + "]\n" +
//        "domain = [" + request.domain + "]\n" +
//        "body = [" + request.body + "]\n" +
//        "headers = [" + request.headers + "]\n" +
//        "method = [" + request.method + "]\n" +
//        "tags = [" + request.tags + "]\n"
//      )
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
//        Ok("Got request [" + request + "]\n" +
//           "query = [" + request.queryString + "]\n" +
//           "host = [" + request.host + "]\n" +
//          "domain = [" + request.domain + "]\n" +
//          "body = [" + request.body + "]\n" +
//          "headers = [" + request.headers + "]\n" +
//          "method = [" + request.method + "]\n" +
//          "tags = [" + request.tags + "]\n"
//        )
    var result : String = ""
//    request.body + ("client_id", JsString("oidcop_client"))
//    request.body + ("client_secret", JsString("oidcop_secret"))
    val clientId = RandomStringUtils.randomAlphanumeric(16)
    val clientSecret = RandomStringUtils.randomAlphanumeric(10)
    val regAccessToken = RandomStringUtils.randomAlphanumeric(10)
    val regClientUri =  RandomStringUtils.randomAlphanumeric(16)
    val jsonClientInfo : JsObject = Json.obj( "client_id" -> clientId,
                                              "client_secret" -> clientSecret,
                                              "registration_access_token" -> regAccessToken,
                                              "registration_client_uri" -> regClientUri
                                            )

    val jsonRequest : JsObject = request.body.as[JsObject]
    var fields : scala.collection.mutable.Map[String, Any] = Client.defaultFields.map{ case (x, y) => {
//      Logger.trace("x = " + x + " class = " + x.getClass + " y = " + jsonRequest \ x)
      jsonRequest \ x match {
        case JsNull => Logger.trace(x + " = none***\n");x -> None
        case yVal : JsUndefined => Logger.trace(x + " = undefined***");x -> None
//        case yVal : JsArray => Logger.trace(x + " = array***\n" + yVal.value.mkString("|") + "\n"); x-> yVal.value.mkString("|")
//        case yVal : JsArray => Logger.trace(x + " = array***\n" + yVal.value.mkString("|") + "\n"); x-> yVal.value.map( f => {f.as[String]}).mkString("|")

        case yVal : JsArray => Logger.trace(x + " = array***\n" + yVal.value.mkString("|") + "\n");
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

    Logger.trace("json = " + jsonRequest.toString)
//    Logger.trace("defaultFields = " + Client.defaultFields)
//    Logger.trace("Fields = " + fields)
    fields("client_id") = clientId
    fields("client_secret") = clientSecret
    fields("registration_access_token") = regAccessToken
    fields("registration_client_uri_path") = regClientUri
    val client = Client(fields)
    Client.insert(client)

    Logger.trace("request class = " + request.getClass)

    val updatedInfo : JsObject = (jsonRequest ++ jsonClientInfo).as[JsObject]
//    request.body.as[JsObject].value.foreach{case(k,v) => result += k + " " + v + "\n"}
//    updatedInfo.value.foreach{case(k,v) => result += k + " " + v + "\n"}
//    Ok(result)
    Ok(Json.prettyPrint(updatedInfo)).as(JSON)

  }

  def auth = StackAction { implicit request =>
    val user : Option[User] = loggedIn
    user match {
      case None => authenticationFailed(request)
//      case x : Option[User] => Ok(request.session.toString + "\n" + user.toString)
      case x : Option[User] => handleAuth(request, user)
    }



  }

  /*
   * sends error output
   *
   */
  def sendError(url : String, error : String, desc : String = "", error_uri : String = "", state : String = "", isQuery : Boolean = true, httpCode : Int = BAD_REQUEST) : Result = {
    Logger.trace("sendError " + error + " : " + desc + " : " + state + " : " + httpCode)
    var params : scala.collection.mutable.Map[String, String] = scala.collection.mutable.Map("error" -> error)
    if(!desc.isEmpty)
      params("desc") = desc
    if(!error_uri.isEmpty)
      params("error_uri") = error_uri
    if(!state.isEmpty)
      params("state") = state

    if(!url.isEmpty) {
      var separator : String = "?"
      if(!isQuery)
        separator = "#"

      val redir : String = String.format("%s%s%s", url, separator, params.map(x => x._1 + "=" + x._2 ).mkString("&"))
      Redirect(redir)
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


  def getRequestParamsAsJson(req : Map[String, String]) : JsObject = {
    val specialKeys : Seq[String] = Seq("claims", "request", "requst_uri")
    val filtered : Map[String, String] = req.filterKeys(p => !specialKeys.contains(p))

    val params = filtered.map {
      case (x, y) => (x,Json.toJsFieldJsValueWrapper(y))
    }

    var jsonParams : JsObject = Json.obj(params.toSeq:_*)
    val claims = req.getOrElse("claims", "")
    if(!claims.isEmpty)
      jsonParams = jsonParams ++ Json.parse(claims).as[JsObject]

    var request = req.getOrElse("request", "")
    val requestUri = req.getOrElse("request_uri", "")
    if(!requestUri.isEmpty)
      request = getSSLURLContents(requestUri)
    if(!request.isEmpty){
      val joseObject : JOSEObject = JOSEObject.parse(request)
      val payload : JsObject = Json.parse(joseObject.getPayload.toString).as[JsObject]
      Logger.trace("req payload = " + payload.toString)
      jsonParams = jsonParams ++ payload
    }
    Logger.trace("final req = " + jsonParams.toString)

    Logger.trace("idtoken claims = " + getIdTokenClaims(jsonParams))
    Logger.trace("userinfo claims = " + getUserInfoClaims(jsonParams))
    jsonParams
  }


  def getRequestClaims(req : JsObject, subKey : String) : Seq[String] = {
    val json : Option[JsObject] = (req \ "claims" \ subKey).asOpt[JsObject]

    json match {
      case None => Seq("")
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
       scopeClaims = scopeClaims ++ Seq("name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_time")
     if(scopes.contains("email"))
       scopeClaims = scopeClaims ++ Seq("email", "email_verified")
     if(scopes.contains("address"))
       scopeClaims = scopeClaims ++ Seq("address", "email_verified")
     if(scopes.contains("phone"))
       scopeClaims = scopeClaims ++ Seq("phone_number", "phone_number_verified")
   }
   val userInfoClaims : Seq[String] = getRequestClaims(req, "userinfo")
   Logger.trace("scope claims = " + scopeClaims)
   Logger.trace("userinfo claims = " + userInfoClaims)
   Logger.trace("all claims = " + (scopeClaims ++ userInfoClaims).toSeq)

   (scopeClaims ++ userInfoClaims).toSet.toSeq
 }

  def getIdTokenClaims(req : JsObject) : Seq[String] = {
    getRequestClaims(req, "id_token")
  }

  def handleAuth(request: Request[AnyContent], user : Option[User]) : Result =  {
    var redirectUri : String = ""
    var state = ""
    var isQuery = true
    try {

      redirectUri = request.getQueryString("redirect_uri").getOrElse("")
      val client = Client.findByClientId(request.getQueryString("client_id").getOrElse(""))
      if(client == None)
        throw OidcException("invalid_request", "no client")


      var queryString : Map[String, Seq[String]] = Map()
      var responseTypes : Array[String] = (request.getQueryString("response_type").getOrElse("")).split(' ').filter(p => !p.isEmpty)
      if(responseTypes.isEmpty)
        throw OidcException("invalid_request", "no response types")

      val scopes : Array[String] = request.getQueryString("scope").getOrElse("").split(' ').filter(p => !p.isEmpty)
      if(scopes.isEmpty)
        throw OidcException("invalid_request", "no scope")
      if(!scopes.contains("openid"))
        throw OidcException("invalid_scope", "no openid scope")

      val state = request.getQueryString("state").getOrElse("")
      val nonce = request.getQueryString("nonce").getOrElse("")

      var codeVal = ""
      var tokenVal = ""
      val idTokenVal = "id_token1"

      var attribList :Array[String] = Array()
      if(scopes.contains("profile"))
        attribList = attribList ++ Array("name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_time")
      if(scopes.contains("email"))
        attribList = attribList ++ Array("email", "email_verified")
      if(scopes.contains("address"))
        attribList = attribList ++ Array("address", "email_verified")
      if(scopes.contains("phone"))
        attribList = attribList ++ Array("phone_number", "phone_number_verified")

      val reqGet = request.queryString.map({case(x,y:Seq[String]) => x-> y.mkString(",")})
      val requestedClaimsJson = getRequestParamsAsJson(reqGet)
      if(responseTypes.contains("code")) {
//        codeVal = RandomStringUtils.randomAlphanumeric(20)
        val codeInfo : JsObject = Token.create_token_info("alice", "Default", attribList.toList, JsObject(reqGet.map({case(x,y) => (x, JsString(y))}).toSeq), requestedClaimsJson)
        codeVal = (codeInfo \ "name").asOpt[String].get
        val code = Token(0, 1, codeVal, Some(0), client.get.fields.get("client_id").asInstanceOf[Option[String]], None, Some(DateTime.now), Some(DateTime.now.plusDays(1)), Some(codeInfo.toString))
        Token.insert(code)
        queryString += "code" -> Seq(codeVal)
      }

      if(responseTypes.contains("token")) {
//        tokenVal = RandomStringUtils.randomAlphanumeric(20)
        val tokenInfo : JsObject = Token.create_token_info("alice", "Default", attribList.toList, JsObject(reqGet.map({case(x,y) => (x, JsString(y))}).toSeq), requestedClaimsJson)
        tokenVal = (tokenInfo \ "name").asOpt[String].get
        val token = Token(0, 1, tokenVal, Some(1), client.get.fields.get("client_id").asInstanceOf[Option[String]], None, Some(DateTime.now), Some(DateTime.now.plusDays(1)), Some(tokenInfo.toString))
        Token.insert(token)
        queryString += "token" -> Seq(tokenVal)
      }

      if(responseTypes.contains("id_token")) {
        val cid : Option[String] = client.get.fields.get("client_id").asInstanceOf[Option[Option[String]]].get
        val idt = getJWS("RS256", makeIdToken(user.get.login, cid.get, Map(), nonce))
        queryString += "id_token" -> Seq(idt )
      }

      if(!state.isEmpty)
        queryString += "state" -> Seq(state)

      Redirect(redirectUri, queryString)
      //      Ok("todo")
    }
    catch {
      case e : NoSuchElementException => { sendError(redirectUri, "invalid_request") }
      case e : OidcException => sendError(redirectUri, e.error, e.desc, e.error_uri, state, isQuery)
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
      Redirect(redirectUri, queryString)
//      Ok("todo")
    }
    catch {
      case e : NoSuchElementException => { BadRequest("Invalid parameters") }
      case e : OidcException => sendError("", "")
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
        case (Some(_), None, None, None) =>  {
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
          Logger.trace("client_secret_post matched");
          tokenEndpointAuthMethod = "client_secret_post"
          Client.findByClientIdAndClientSecret(clientId.get, clientSecret.get)
        }
        case (Some(_), None, Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), Some(_)) =>  {
          Logger.trace("client_secret_jwt matched");
          tokenEndpointAuthMethod = "client_secret_jwt"
          val jwsObj : JWSObject = JWSObject.parse(assertion.get)
          val jwsHeader = jwsObj.getHeader
          Logger.trace("jws headers = " + jwsHeader);
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

        case (Some(_), None, Some("private_key_jwt"), Some(_)) => {
          Logger.trace("private_key_jwt matched");
          tokenEndpointAuthMethod = "private_key_jwt"
          None
        }
        case _ => Logger.trace("none matched"); None
      }

      Logger.trace("auth method = " + tokenEndpointAuthMethod)

      dbClient match {
        case None => false
        case c : Option[Client] => {
          tokenEndpointAuthMethod = c.get.fields("token_endpoint_auth_method").asInstanceOf[Option[String]].getOrElse("client_secret_basic")
          Logger.trace("auth method1 = " + tokenEndpointAuthMethod + " len = " + tokenEndpointAuthMethod.length)
          Logger.trace("auth method = " + tokenEndpointAuthMethod + " class = " + tokenEndpointAuthMethod.getClass)
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
              true
              // val jwsVerifier : JWSVerifier = new RSASSAVerifier()(c.fields("client_secret").asInstanceOf[Option[String]].get.getBytes)
              // jwsObject.verify(jwsVerifier)
            }


            case e : String => Logger.trace("all skipped : method = " + e); false
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

/*

      if(responseTypes.contains("token")) {
//        tokenVal = RandomStringUtils.randomAlphanumeric(20)
        val tokenInfo : JsObject = Token.create_token_info("alice", "Default", List("a", "b", "c"), reqGet, reqGet)
        tokenVal = (tokenInfo \ "name").asOpt[String].get
        val token = Token(0, 1, tokenVal, Some(1), Some("http://client1"), Some("details"), Some(DateTime.now), Some(DateTime.now.plusDays(1)), Some(tokenInfo.toString))
        Token.insert(token)
        queryString += "token" -> Seq(tokenVal)
      }

 */
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
      val idTokenClaimsList = getIdTokenClaims((jsonReq \ "r").as[JsObject] )
      Logger.trace("idtoken claims = " + idTokenClaimsList)
      val persona = Persona.findByAccountPersona(account, (jsonReq \ "p").asOpt[String].getOrElse("Default")).get
      val idTokenClaims : Map[String, Any] = idTokenClaimsList.map{ claimName =>
        claimName match {
          case "phone_number_verified" | "email_verified" => persona.fields.getOrElse(claimName, Some(0)).asInstanceOf[Option[Int]].get match {
            case 0 => (claimName, false)
            case 1 => (claimName, true)
          }
//          case "address" => (claimName, new net.minidev.json.JSONObject().put("formatted", persona.fields.getOrElse(claimName, Some("")).asInstanceOf[Option[String]].get))
          case "address" => val addressMap = new java.util.HashMap[String, java.lang.Object]; addressMap.put("formatted", persona.fields.getOrElse(claimName, Some("")).asInstanceOf[Option[String]].get);(claimName, addressMap)
          case "updated_time" => (claimName, persona.fields.getOrElse(claimName, Some(DateTime.now)).asInstanceOf[Option[DateTime]].get)
          case field : String => (field, persona.fields.getOrElse(field, Some("")).asInstanceOf[Option[String]].get)
        }
      }.toMap

      val jsonResponse = Json.obj(
        "access_token" -> dbToken.token,
        "id_token" -> getJWS("RS256", makeIdToken(account.login, dbToken.client.get, idTokenClaims,(jsonReq \ "r" \ "nonce").asOpt[String].getOrElse(""))),
        "token_type" -> "bearer",
        "expires_in" -> 3600
      )
      Ok(Json.prettyPrint(jsonResponse)).as(JSON).withHeaders(("Cache-Control", "no-store"), ("Pragma","no-cache"))
    }
    catch {
      case e : OidcException => sendError("", e.error, e.desc, e.error_uri)
      case e : Throwable => sendError("", "invalid_request", "exception: " + e.toString)
    }

  }


// def getIdTokenClaims(allowedList : Seq[String], reqParams : Map[String, String]) : Seq[String] = {
//
//
//   Seq("")
// }

//  def getUserInfoClaims(jsonReq : JsValue) : Seq[String] = {
//
//    val allowedList : Array[String] = (jsonReq \ "l").as[Array[String]]
//    val persona : String = (jsonReq \ "p").as[String]
//    val scopes : Array[String] = (jsonReq \ "r" \ "scope").as[String].split(' ')
//
//    var attribList :Array[String] = Array()
//    if(scopes.contains("profile"))
//      attribList = attribList ++ Array("name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_time")
//    if(scopes.contains("email"))
//      attribList = attribList ++ Array("email", "email_verified")
//    if(scopes.contains("address"))
//      attribList = attribList ++ Array("address", "email_verified")
//    if(scopes.contains("phone"))
//      attribList = attribList ++ Array("phone_number", "phone_number_verified")
//    allowedList.filter(f => attribList.contains(f))
//  }


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

      val allowedUserInfoClaims : Seq[String] = (getUserInfoClaims((jsonReq \ "r").as[JsObject]) ++ List("sub")).asInstanceOf[Seq[String]]
      Logger.trace("userinfo allowed list = " + allowedUserInfoClaims)

      val returnClaims = allowedUserInfoClaims.map(f => f match {
          case "sub"  => (f, Json.toJsFieldJsValueWrapper(account.login))
          case "phone_number_verified" | "email_verified" => persona.fields.getOrElse(f, Some(0)).asInstanceOf[Option[Int]].get match {
                                                            case 0 => (f, Json.toJsFieldJsValueWrapper(false))
                                                            case 1 => (f, Json.toJsFieldJsValueWrapper(true))
                                                         }
          case "address" => (f, Json.toJsFieldJsValueWrapper(Json.obj("formatted"->persona.fields.getOrElse(f, Some("")).asInstanceOf[Option[String]].get)))
          case "updated_time" => (f, Json.toJsFieldJsValueWrapper(persona.fields.getOrElse(f, Some(DateTime.now)).asInstanceOf[Option[DateTime]].get))
          case field : String => (field, Json.toJsFieldJsValueWrapper(persona.fields.getOrElse(field, Some("")).asInstanceOf[Option[String]].get))
        }
      )

      Logger.trace("claims = " + returnClaims)
      Logger.trace("claims map = " + returnClaims.toMap)

      val jsonClaims = Json.obj(returnClaims.toSeq:_*)

      Ok(Json.prettyPrint(jsonClaims)).as(JSON)


    }
    catch {
      case e : OidcException => Logger.trace("userinfo exception " + e); sendBearerError(e.error, e.desc, UNAUTHORIZED)
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
//        "updated_time" -> "2013-03-30 09:00"
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
    val in : InputStream = new URL(url).openStream();
    try {
      IOUtils.toString(in)
    } finally {
      IOUtils.closeQuietly(in);
    }
  }

  def getSSLURLContents(url : String) : String = {
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

  def makeIdToken(sub : String, client : String, claims : Map[String, Any] = Map(), nonce : String = "") : String = {

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
    claims.foreach{ case (key, value) => jwtClaims.setCustomClaim(key, value)}
    if(!nonce.isEmpty)
      jwtClaims.setCustomClaim("nonce", nonce)
    Logger.trace("idtoken string = " + jwtClaims.toJSONObject.toJSONString)
    jwtClaims.toJSONObject.toJSONString
  }

  def getJWS(alg : String, payloadStr : String) : String = {
    var jwsAlg : JWSAlgorithm = new JWSAlgorithm(alg)
    val privKey : RSAPrivateKey = getOpPrivateKey.asInstanceOf[RSAPrivateKey]
    var jwsSigner : JWSSigner = null
    alg.substring(0, 2) match {
      case "HS" => jwsSigner  = new MACSigner(alg.getBytes)
      case "RS" => jwsSigner  = new RSASSASigner(privKey)
    }


    val header = new JWSHeader(jwsAlg)
    header.setKeyID("key00")
    val payload = new PayloadExtStr(payloadStr)
    val jwsObject = new JWSObject(header, payload)

    jwsObject.sign(jwsSigner)

    val jws : String = jwsObject.serialize()
    Logger.trace("JWS signature = " + jws)
    jws
  }



  def dbTest = Action { implicit request =>
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

        val decodedPub : Array[Byte] = org.apache.commons.codec.binary.Base64.decodeBase64(pubKeyPEM)
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
        Ok(result.toString() + "\n" + tok).withSession(session + ("k1"->"p1"))





      }

    }
    catch {
      case unknown : Throwable => { BadRequest(unknown.toString)}
    }
  }

  def jwkTest = Action { implicit request =>

    try {

      val opPrivatekey : RSAPrivateCrtKey = getDerRSAPrivateKey("/home/edmund/work/abop/testkeys/speckeys/op_private.pkcs8").asInstanceOf[RSAPrivateCrtKey]
      val opPublicKey : RSAPublicKey = getX509PublicKey("/home/edmund/work/abop/testkeys/speckeys/op_public_cert.pem").asInstanceOf[RSAPublicKey]

      val rpPrivatekey : RSAPrivateCrtKey = getDerRSAPrivateKey("/home/edmund/work/abop/testkeys/speckeys/rp_private.pkcs8").asInstanceOf[RSAPrivateCrtKey]
      val rpPublicKey : RSAPublicKey = getX509PublicKey("/home/edmund/work/abop/testkeys/speckeys/rp_public_cert.pem").asInstanceOf[RSAPublicKey]

//      val rsaMulti : RSAMultiPrimePrivateCrtKey = null

//      val rsaMultiPrimePrivateCrtKeySpec : RSAMultiPrimePrivateCrtKeySpec = new RSAMultiPrimePrivateCrtKeySpec(opPrivatekey.getModulus, opPrivatekey.get)

      val rsaOPKey = new RSAKey(opPublicKey, opPrivatekey, null, null, null)
      val rsaRPKey = new RSAKey(rpPublicKey, rpPrivatekey, null, null, null)


      val jwkString = "OP JWK :\n" + rsaOPKey.toJSONString + "\nRP JWK :\n" + rsaRPKey.toJSONString
      Logger.trace(jwkString)

      Ok(jwkString).as(TEXT)
    }
    catch {
      case e : Throwable => {BadRequest(e.toString)}
    }
  }

}