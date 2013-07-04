package models
import java.util.{Date}

import play.api.Logger
import play.api.db._
import play.api.Play.current

import anorm._
import anorm.SqlParser._
import org.joda.time._
import org.joda.time.format._
import utils.AnormExtensions._
import scala.collection.mutable.Map

import models._


/**
 * Created with IntelliJ IDEA.
 * User: edmund
 * Date: 5/17/13
 * Time: 5:09 PM
 * To change this template use File | Settings | File Templates.
 */

case class Persona( var fields : Map[String, Any] )

object Persona {

  // -- Parsers

  /**
   * Parse a Persona from a ResultSet
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) NOT NULL,
  `persona_name` varchar(255) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `given_name` varchar(255) DEFAULT NULL,
  `given_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `given_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `family_name` varchar(255) DEFAULT NULL,
  `family_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `family_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `middle_name` varchar(255) DEFAULT NULL,
  `middle_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `middle_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `nickname` varchar(255) DEFAULT NULL,
  `preferred_username` varchar(255) DEFAULT NULL,
  `profile` varchar(255) DEFAULT NULL,
  `picture` varchar(255) DEFAULT NULL,
  `website` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `email_verified` tinyint(4) DEFAULT '0',
  `gender` varchar(255) DEFAULT NULL,
  `birthdate` varchar(255) DEFAULT NULL,
  `zoneinfo` varchar(255) DEFAULT NULL,
  `locale` varchar(255) DEFAULT NULL,
  `phone_number` varchar(255) DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `updated_time` datetime DEFAULT NULL,
   */
  val simple = {
      get[Long]("personas.id") ~
      get[Long]("personas.account_id") ~
      get[String]("personas.persona_name") ~
      get[Option[String]]("personas.name") ~
      get[Option[String]]("personas.name_ja_kana_jp") ~
      get[Option[String]]("personas.name_ja_hani_jp") ~
      get[Option[String]]("personas.given_name") ~
      get[Option[String]]("personas.given_name_ja_kana_jp") ~
      get[Option[String]]("personas.given_name_ja_hani_jp") ~
      get[Option[String]]("personas.family_name") ~
      get[Option[String]]("personas.family_name_ja_kana_jp") ~
      get[Option[String]]("personas.family_name_ja_hani_jp") ~
      get[Option[String]]("personas.middle_name") ~
      get[Option[String]]("personas.middle_name_ja_kana_jp") ~
      get[Option[String]]("personas.middle_name_ja_hani_jp") ~
      get[Option[String]]("personas.nickname") ~
      get[Option[String]]("personas.preferred_username") ~
      get[Option[String]]("personas.profile") ~
      get[Option[String]]("personas.picture") ~
      get[Option[String]]("personas.website") ~
      get[Option[String]]("personas.email") ~
      get[Option[Boolean]]("personas.email_verified") ~
      get[Option[String]]("personas.gender") ~
      get[Option[String]]("personas.birthdate") ~
      get[Option[String]]("personas.zoneinfo") ~
      get[Option[String]]("personas.locale") ~
      get[Option[String]]("personas.phone_number") ~
      get[Option[Boolean]]("personas.phone_number_verified") ~
      get[Option[String]]("personas.address") ~
      get[Option[DateTime]]("personas.updated_at") map {
      case id~account_id~persona_name~name~name_ja_kana_jp~name_ja_hani_jp~given_name~given_name_ja_kana_jp~given_name_ja_hani_jp~family_name~family_name_ja_kana_jp~family_name_ja_hani_jp~middle_name~middle_name_ja_kana_jp~middle_name_ja_hani_jp~nickname~preferred_username~profile~picture~website~email~email_verified~gender~birthdate~zoneinfo~locale~phone_number~phone_number_verified~address~updated_at
      => Persona( Map(
                      "id"->id,
                      "account_id"->account_id,
                      "persona_name"->persona_name,
                      "name"->name,
                      "name_ja_kana_jp"->name_ja_kana_jp,
                      "name_ja_hani_jp"->name_ja_hani_jp,
                      "given_name"->given_name,
                      "given_name_ja_kana_jp"->given_name_ja_kana_jp,
                      "given_name_ja_hani_jp"->given_name_ja_hani_jp,
                      "family_name"->family_name,
                      "family_name_ja_kana_jp"->family_name_ja_kana_jp,
                      "family_name_ja_hani_jp"->family_name_ja_hani_jp,
                      "middle_name"->middle_name,
                      "middle_name_ja_kana_jp"->middle_name_ja_kana_jp,
                      "middle_name_ja_hani_jp"->middle_name_ja_hani_jp,
                      "nickname"->nickname,
                      "preferred_username"->preferred_username,
                      "profile"->profile,
                      "picture"->picture,
                      "website"->website,
                      "email"->email,
                      "email_verified"->email_verified,
                      "gender"->gender,
                      "birthdate"->birthdate,
                      "zoneinfo"->zoneinfo,
                      "locale"->locale,
                      "phone_number"->phone_number,
                      "phone_number_verified"->phone_number_verified,
                      "address"->address,
                      "updated_at"->updated_at
                    )
                )
    }
  }



  /*
  * Finds Persona By Account_id and Persona
  */
  def findByAccountPersona(account : Account, persona_name : String): Option[Persona] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from personas where account_id = {account_id} and persona_name = {persona_name}").on("account_id"->account.id, "persona_name" -> persona_name).as(Persona.simple.singleOpt)
      }
    }
    catch {
      case unknown : Throwable => {
        Logger.trace("Client.findByClientId exception " + unknown)
        None
      }
    }
  }


  /**
   * List all the Personas
   */
  def list(): List[Persona] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from personas").as(Persona.simple *)
      }
    }
    catch {
      case unknown : Throwable => { Logger.trace("Persona.list exception " + unknown); List() }
    }
  }


}
