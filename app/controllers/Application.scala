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

object Application extends Controller with LoginLogout with AuthConfigImpl {
  
  def index = Action {
    Ok(views.html.index("Your new application is ready."))
  }

  def discover = Action {
    Ok(views.html.index("Hello World"))
  }

  val loginForm = Form {
    mapping("login" -> text, "password" -> text)(Account.authenticate)(_.map(u => (u.login, "")))
      .verifying("Invalid email or password", result => result.isDefined)
  }

  def login = Action { implicit request =>
    println("start login")
    Ok(html.login(loginForm))
  }

  def logout = Action { implicit request =>
    gotoLogoutSucceeded.flashing(
      "success" -> "You've been logged out"
    )
  }

  def authenticate = Action { implicit request =>
    println("start act")

    loginForm.bindFromRequest.fold(
      formWithErrors => { println("form eror"); BadRequest(html.login(formWithErrors))},
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
    val uri = request.session.get("access_uri").getOrElse(routes.Messages.main.url.toString)
    val fmt : DateTimeFormatter = DateTimeFormat.forPattern("yyyyMMdd HHmmss z");
    val sessionId =  RandomStringUtils.randomAlphabetic(20);
    val sessionParams : Map[String, Any] = Map("auth_time"-> DateTime.now);
    Cache.set("session." + sessionId, sessionParams)
    Redirect(uri).withSession(request.session - "access_uri" + ("sessionid" -> sessionId) + ("login_time" -> DateTime.now.toString(ISODateTimeFormat.dateTime)))
  }

  def logoutSucceeded(request: RequestHeader) = {
    Cache.remove("session." + request.session.get("sessionid").get)
    Redirect(routes.Application.login).withNewSession
  }

  def authenticationFailed(request: RequestHeader) = Redirect(routes.Application.login).withSession("access_uri" -> request.uri)

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