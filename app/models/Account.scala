package models
import java.util.{Date}

import play.api.Logger
import play.api.db._
import play.api.Play.current

import anorm._
import anorm.SqlParser._

import models._

case class Account(id: Long, var login: String, var crypted_password: String, var enabled: Int, var permission: Permission)

/**
 * Created with IntelliJ IDEA.
 * User: Edmund
 * Date: 4/25/13
 * Time: 5:40 PM
 * To change this template use File | Settings | File Templates.
 */
object Account {

  // -- Parsers

  /**
   * Parse a Computer from a ResultSet
   */
  val simple = {
    get[Long]("accounts.id") ~
      get[String]("accounts.login") ~
      get[String]("accounts.crypted_password") ~
      get[Int]("accounts.enabled") map {
      case id~login~crypted_password~enabled => Account(id, login, crypted_password, enabled, NormalUser)
    }
  }


  /**
   * Authenticates account name and password.
   */
  def authenticate(name : String, password : String): Option[Account] = {
    try {
      DB.withConnection { implicit conn =>
      SQL("select * from accounts where login = {name} and crypted_password = sha1({password})").on("name"->name, "password"->password).as(Account.simple.singleOpt)
      }
    }
    catch {
    case unknown : Throwable => {
      Logger.trace("authenticate exception " + unknown)
      None
      }
    }
  }

  /**
   * Finds Account By Id
   */
  def findById(id : Long): Option[Account] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from accounts where id = {id}").on("id"->id).as(Account.simple.singleOpt)
      }
    }
    catch {
      case unknown : Throwable => {
        Logger.trace("findById exception " + unknown)
        None
      }
    }
  }


  /**
   * Finds Account By Id
   */
  def findByLogin(login : String): Option[Account] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from accounts where login = {login}").on("login"->login).as(Account.simple.singleOpt)
      }
    }
    catch {
      case unknown : Throwable => {
        Logger.trace("findByLogin exception " + unknown)
        None
      }
    }
  }


  /**
   * List all the accounts
   */
  def list(): List[Account] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from accounts").as(Account.simple *)
      }
    }
    catch {
      case unknown : Throwable => List()
    }
  }


  /**
   * Update a computer.
   *
   * @param id The account id
   * @param account The account values.
   */
  def update(id: Long, account: Account) = {
    DB.withConnection { implicit connection =>
      SQL(
        """
          update accounts
          set login = {login}, crypted_password = sha1({password}), enabled = {enabled}
          where id = {id}
        """
      ).on(
        'id -> id,
        'login -> account.login,
        'crypted_password -> account.crypted_password,
        'enabled -> account.enabled
      ).executeUpdate()
    }
  }

  /**
   * Insert a new account.
   *
   * @param account The account values.
   */
  def insert(account: Account) = {
    DB.withConnection { implicit connection =>
      SQL(
        """
          insert into accounts (`login`, `crypted_password`, `enabled` ) values (
            {login}, {crypted_password}, {enabled}
          )
        """
      ).on(
        'login -> account.login,
        'crypted_password -> account.crypted_password,
        'enabled -> account.enabled
      ).executeUpdate()
    }
  }

  /**
   * Delete a computer.
   *
   * @param id Id of the account to delete.
   */
  def delete(id: Long) = {
    DB.withConnection { implicit connection =>
      SQL("delete from accounts where id = {id}").on('id -> id).executeUpdate()
    }
  }



}
