package models

import anorm.SqlParser._
import anorm._
import play.api.db.DB
import anorm.~
import play.api.Logger
import play.api.Play.current

/**
 * Created with IntelliJ IDEA.
 * User: edmund
 * Date: 7/1/13
 * Time: 5:36 PM
 * To change this template use File | Settings | File Templates.
 */
case class TrustedSite(id : Long, accountId: Long, personaId : Long, url : String)



object TrustedSite {

  /**
   * Parse a Computer from a ResultSet
   */
  val simple = {
      get[Long]("sites.id") ~
      get[Long]("sites.account_id") ~
      get[Long]("sites.persona_id") ~
      get[String]("sites.url") map {
      case id~account_id~persona_id~url => TrustedSite(id, account_id, persona_id, url)
    }
  }


  def paramsToInsert(params: Seq[(Any, ParameterValue[_])]): String =
    "(" + params.map(_._1).mkString(",") + ") VALUES " +
      "(" + params.map("{" + _._1 + "}").mkString(",") + ")"

  def paramsToUpdate(params: Seq[(Any, ParameterValue[_])]): String =
    "SET " + params.map({case(x,y) => x + "={" + x + "}"}).mkString(",") + " WHERE id={id}"

  def insertTable(ps: Seq[(Any, ParameterValue[_])]) = DB.withConnection { implicit c =>
    SQL("INSERT INTO sites " + paramsToInsert(ps)).on(ps:_*).execute
  }

  def updateTable(ps: Seq[(Any, ParameterValue[_])]) = DB.withConnection { implicit c =>
    SQL("UPDATE sites " + paramsToUpdate(ps)).on(ps:_*).execute
  }

  /** re-usable mapping */
  def toParams(trustedSite: TrustedSite): Seq[(Any, ParameterValue[_])] = Seq(
    "account_id" -> trustedSite.accountId,
    "persona_id" -> trustedSite.personaId,
    "url" -> trustedSite.url
  )


  def insert(trustedSite: TrustedSite) { insertTable(toParams(trustedSite)) }


  /**
   * Update a TrustedSite.
   *
   * @param trustedSite The client values.
   */
  def update(trustedSite: TrustedSite) = {
    val s1 : Seq[(Any, ParameterValue[_])] = Seq("id" -> trustedSite.id)
    updateTable(toParams(trustedSite)++s1)
  }


  /**
   * Delete a TrustedSite.
   *
   * @param id Id of the token to delete.
   */
  def delete(id: Long) = {
    DB.withConnection { implicit connection =>
      SQL("delete from sites where id = {id}").on('id -> id).executeUpdate()
    }
  }

  /**
   * Finds Site By Account, Persona, and Client
   */
  def findByAccountPersonaClient(account : String, persona : String, client : String): Option[TrustedSite] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select sites.id, sites.account_id, sites.persona_id, sites.url from sites left join accounts on sites.account_id = accounts.id left join personas on sites.persona_id = personas.id where accounts.login = {login} and personas.persona_name = {persona} and sites.url = {client}").on("login"->account, "persona"->persona, "client"->client).as(TrustedSite.simple.singleOpt)
      }
    }
    catch {
      case unknown : Throwable => {
        Logger.trace("TrustedSites.findByAccountPersonaClient exception " + unknown)
        None
      }
    }
  }

  /**
   * Finds TrustedSite by Account and Client
   */
  def findByAccountClient(account : String, client : String): Option[TrustedSite] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select sites.id, sites.account_id, sites.persona_id, sites.url from sites left join accounts on sites.account_id = accounts.id where accounts.login = {login} and sites.url = {client}").on("login"->account, "client"->client).as(TrustedSite.simple.singleOpt)
      }
    }
    catch {
      case unknown : Throwable => {
        Logger.trace("TrustedSites.findByAccountClient exception " + unknown)
        None
      }
    }
  }


}
