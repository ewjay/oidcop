package controllers

/**
 * Created with IntelliJ IDEA.
 * User: Edmund
 * Date: 4/25/13
 * Time: 12:03 PM
 * To change this template use File | Settings | File Templates.
 */
class OpenidConnectData {

}


class OpenidAuthRequest {

}

/*
case class User(id: Long, name: String, friends: List[User])

implicit object UserFormat extends Format[User] {
  def reads(json: JsValue): User = User(
    (json \ "id").as[Long],
    (json \ "name").as[String],
    (json \ "friends").asOpt[List[User]].getOrElse(List()))
  def writes(u: User): JsValue = JsObject(List(
    "id" -> JsNumber(u.id),
    "name" -> JsString(u.name),
    "friends" -> JsArray(u.friends.map(fr => JsObject(List("id" -> JsNumber(fr.id),
      "name" -> JsString(fr.name)))))))
}
*/
