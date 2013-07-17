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
case class TrustedSite(id : Long, accountId: Long, personaId : Long, clientId : String)



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


  /**
   * Finds Account By Id
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


}
