package controllers

import play.api._
import play.api.mvc._
import jp.t2v.lab.play2.auth._
import play.api.Play._
import play.api.cache.Cache
import reflect.classTag
import jp.t2v.lab.play2.stackc.{RequestWithAttributes, RequestAttributeKey, StackableController}
import models._
import play.api.mvc.Results._
import play.api.templates.Html
import views.html
import play.api.data.Form
import play.api.data.Forms._
import scala.reflect.ClassTag
import org.apache.commons.lang3.RandomStringUtils
import org.joda.time.DateTime
import org.joda.time.format.{ISODateTimeFormat, DateTimeFormat, DateTimeFormatter}
import play.core.Router

object Application extends Controller with LoginLogout with AuthConfigImpl {
  
  def index = Action {
    Ok(views.html.index("Your new application is ready."))
  }

  def discover = Action {
    Ok(views.html.index("Hello World"))
  }

  val loginForm = Form {
    mapping("login" -> default(text, "alice"), "password" -> default(text, "wonderland"))(Account.authenticate)(_.map(u => (u.login, "")))
      .verifying("Invalid email or password", result => result.isDefined)
  }

  def login = Action { implicit request =>
    println("start login")

    var logo_uri : String = ""
    var policy_uri : String = ""
    var sessionAccessUri : Option[String] = request.session.get("sessionAccessUri")
    sessionAccessUri match {
      case None => {}
      case _ => {
        val sessionParams : Map[String, Any] = Cache.get("sessionAccessUri." + sessionAccessUri.getOrElse("")).get.asInstanceOf[Map[String, Any]]
        logo_uri = sessionParams("logo_uri").asInstanceOf[String]
        policy_uri = sessionParams("policy_uri").asInstanceOf[String]
      }
    }

    Ok(html.login(loginForm, logo_uri, policy_uri))
  }

  def logout = Action { implicit request =>
    gotoLogoutSucceeded.flashing(
      "success" -> "You've been logged out"
    )
  }

  def authenticate = Action { implicit request =>
    println("start act")

    loginForm.bindFromRequest.fold(
      formWithErrors => { println("form eror");
        var logo_uri : String = ""
        var policy_uri : String = ""
        var sessionAccessUri : Option[String] = request.session.get("sessionAccessUri")
        sessionAccessUri match {
          case None => {}
          case _ => {
            val sessionParams : Map[String, Any] = Cache.get("sessionAccessUri." + sessionAccessUri.getOrElse("")).get.asInstanceOf[Map[String, Any]]
            logo_uri  = sessionParams("logo_uri").asInstanceOf[String]
            policy_uri = sessionParams("policy_uri").asInstanceOf[String]
          }
        }
        BadRequest(html.login(formWithErrors, logo_uri, policy_uri))},
      user => gotoLoginSucceeded(user.get.id)
    )
  }

}


trait Messages extends Controller with Pjax with AuthElement with AuthConfigImpl {

  def main = StackAction(AuthorityKey -> NormalUser) { implicit request =>
    val user = loggedIn
    val title = "message main " + user.login
    Ok(html.message.main(title))
  }

  def list = StackAction(AuthorityKey -> NormalUser) { implicit request =>
    val title = "all messages"
    Ok(html.message.list(title))
  }

  def detail(id: Int) = StackAction(AuthorityKey -> NormalUser) { implicit request =>
    val title = "messages detail "
    Ok(html.message.detail(title + id))
  }

  def write = StackAction(AuthorityKey -> Administrator) { implicit request =>
    val title = "write message"
    Ok(html.message.write(title))
  }

}

object Messages extends Messages
trait AuthConfigImpl extends AuthConfig {

  type Id = Long

  type User = Account

  type Authority = Permission

//  val idTag = classTag[Id]
  val idTag: ClassTag[Id] = classTag[Id]

  val sessionTimeoutInSeconds = 3600

  def resolveUser(id: Id) = Account.findById(id)

  def loginSucceeded(request: RequestHeader) : Result = {
    // val uri = request.session.get("access_uri").getOrElse(routes.Messages.main.url.toString)
    var sessionAccessUri : Option[String] = request.session.get("sessionAccessUri")
    var uri : String = routes.Messages.main.url.toString
    var query : Map[String, Seq[String]] = Map()
    sessionAccessUri match {
      case None => {}
      case _ => {
        val sessionParams : Map[String, Any] = Cache.get("sessionAccessUri." + sessionAccessUri.getOrElse("")).get.asInstanceOf[Map[String, Any]]
        uri = sessionParams("access_uri").asInstanceOf[String]
        query = sessionParams("query").asInstanceOf[Map[String, Seq[String]]]
        Logger.trace("uri = " + uri)
        Logger.trace("query = " + query.toString())
        Cache.remove("sessionAccessUri." + sessionAccessUri)
      }
    }

    val fmt : DateTimeFormatter = DateTimeFormat.forPattern("yyyyMMdd HHmmss z");
    val sessionId =  RandomStringUtils.randomAlphabetic(20);
    val sessionParams : Map[String, Any] = Map("auth_time"-> DateTime.now);
    Cache.set("session." + sessionId, sessionParams)
    Logger.trace("headers = " + request.headers.toString)
//    Redirect(uri).withSession(request.session - "access_uri" + ("sessionid" -> sessionId) + ("login_time" -> DateTime.now.toString(ISODateTimeFormat.dateTime))).flashing(("relogin", "1"))
    val cookies : Cookie  = Cookie("ops", sessionId, None, "/", None, false, false)
    Logger.trace("loginsucceeded session = " + request.session)
    Redirect(uri, query).withSession(request.session - "sessionAccessUri" + ("sessionid" -> sessionId) + ("login_time" -> DateTime.now.toString(ISODateTimeFormat.dateTime))).withCookies(cookies).flashing(("relogin", "1"))
  }

  def logoutSucceeded(request: RequestHeader) = {
    Logger.trace("logoutsucceeded session = " + request.session)
    try{
      Cache.remove("session." + request.session.get("sessionid").get)
    }
    catch {
      case e : NoSuchElementException =>
    }
    val cookies : Cookie  = Cookie("ops", "", Some(-1), "/", None, false, false)
    val logoutRedirectUri : String = request.getQueryString("post_logout_redirect_uri").getOrElse("")
    if(logoutRedirectUri.isEmpty)
      Redirect(routes.Application.login).withNewSession.withCookies(cookies)
    else
      Ok(views.html.endsession(logoutRedirectUri)).withNewSession.withCookies(cookies)
  }

  def authenticationFailed(request: RequestHeader) = {
    var url : String = routes.Application.login.absoluteURL(true)(request)
    Logger.trace("*** auth failed for " + request.uri)
    Logger.trace("is request = " + request.isInstanceOf[Request[AnyContent]].toString)
    if(request.isInstanceOf[Request[AnyContent]]) {
      val req : Request[AnyContent] = request.asInstanceOf[Request[AnyContent]]
      Logger.trace("req method =" + req.method)
      Logger.trace("req domain =" + req.domain)
      Logger.trace("req host =" + req.host)
      Logger.trace("req path =" + req.path)
      Logger.trace("req uri =" + req.uri)

    }
    val access_uri : String = "https://" + request.host + request.path
//    val access_uri : String =  request.uri
    val sessionId =  RandomStringUtils.randomAlphabetic(20);

    val client : Option[Client] = Client.findByClientId(request.getQueryString("client_id").getOrElse(""))
    var logo_uri =  ""
    var policy_uri = ""
    client match {
      case None =>
      case Some(_) =>
        logo_uri = client.get.fields.get("logo_uri").asInstanceOf[Option[Option[String]]].get.getOrElse("")
        policy_uri = client.get.fields.get("policy_uri").asInstanceOf[Option[Option[String]]].get.getOrElse("")
    }

    val sessionParams : Map[String, Any] = Map("access_uri"-> access_uri, "query" -> request.queryString, "logo_uri" -> logo_uri, "policy_uri" -> policy_uri);
    Cache.set("sessionAccessUri." + sessionId, sessionParams)
    Logger.trace("access_uri =" + access_uri)
    Redirect(url).withSession("sessionAccessUri" -> sessionId)
  }

  def authorizationFailed(request: RequestHeader) = Forbidden("no permission")

  def authorize(user: User, authority: Authority) = (user.permission, authority) match {
    case (Administrator, _) => true
    case (NormalUser, NormalUser) => true
    case _ => false
  }

  //  override lazy val idContainer = new CookieIdContainer[Id]

}

trait Pjax extends StackableController {
  self: Controller with AuthElement with AuthConfigImpl =>

  type Template = String => Html => Html

  case object TemplateKey extends RequestAttributeKey[Template]

  abstract override def proceed[A](req: RequestWithAttributes[A])(f: RequestWithAttributes[A] => Result): Result = {
    val template: Template = if (req.headers.keys("X-Pjax")) html.pjaxTemplate.apply else html.fullTemplate.apply(loggedIn(req))
    super.proceed(req.set(TemplateKey, template))(f)
  }

  implicit def template[A](implicit req: RequestWithAttributes[A]): Template = req.get(TemplateKey).get

}