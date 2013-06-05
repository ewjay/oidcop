package models
import java.util.{Date}

import play.api.Logger
import play.api.db._
import play.api.Play.current

import anorm._
import anorm.SqlParser._
import scala.collection.mutable.Map
import models._


//case class Client(
//                    id: Long,
//                    client_id : String,
//                    client_secret : String,
//                    client_secret_expires_at : Long,
//                    registration_access_token : String,
//                    registration_client_uri_path : String,
//                    contacts : String,
//                    application_type : String,
//                    client_name : String,
//                    logo_uri : String,
//                    tos_uri : String,
//                    redirect_uris : String,
//                    token_endpoint_auth_method : String,
//                    policy_uri : String,
//                    jwks_uri : String,
//                    jwk_encryption_uri : String,
//                    x509_uri : String,
//                    x509_encryption_uri : String,
//                    sector_identifier_uri : String,
//                    javascript_origin_uris : String,
//                    subject_type : String,
//                    request_object_signing_alg : String,
//                    userinfo_signed_response_alg : String,
//                    userinfo_encrypted_response_alg : String,
//                    userinfo_encrypted_response_enc : String,
//                    id_token_signed_response_alg : String,
//                    id_token_encrypted_response_alg : String,
//                    id_token_encrypted_response_enc : String,
//                    default_max_age : Int,
//                    require_auth_time : Int,
//                    default_acr_values : String,
//                    initiate_login_uri : String,
//                    post_logout_redirect_uri : String,
//                    request_uris : String,
//                    grant_types : String,
//                    response_types : String
//                 )

case class Client( var fields : Map[String, Any] )



/**
 * Created with IntelliJ IDEA.
 * User: edmund
 * Date: 5/17/13
 * Time: 11:58 AM
 * To change this template use File | Settings | File Templates.
 */
object Client {

  // -- Parsers
  val defaultFields : Map[String, Any] = Map(
    "id"-> None,
    "client_id"-> None,
    "client_secret" -> None,
    "client_secret_expires_at" -> None,
    "registration_access_token" -> None,
    "registration_client_uri_path" -> None,
    "contacts" -> None,
    "application_type" -> None,
    "client_name" -> None,
    "logo_uri" -> None,
    "tos_uri" -> None,
    "redirect_uris" -> None,
    "token_endpoint_auth_method" -> None,
    "policy_uri" -> None,
    "jwks_uri" -> None,
    "jwk_encryption_uri" -> None,
    "x509_uri" -> None,
    "x509_encryption_uri" -> None,
    "sector_identifier_uri" -> None,
    "javascript_origin_uris" -> None,
    "subject_type" -> None,
    "request_object_signing_alg" -> None,
    "userinfo_signed_response_alg" -> None,
    "userinfo_encrypted_response_alg" -> None,
    "userinfo_encrypted_response_enc" -> None,
    "id_token_signed_response_alg" -> None,
    "id_token_encrypted_response_alg" -> None,
    "id_token_encrypted_response_enc" -> None,
    "default_max_age" -> None,
    "require_auth_time" -> None,
    "default_acr_values" -> None,
    "initiate_login_uri" -> None,
    "post_logout_redirect_uri" -> None,
    "request_uris" -> None,
    "grant_types" -> None,
    "response_types" -> None
    )

  /**
   * Parse a Client from a ResultSet
   */
  val simple = {
      get[Option[Long]]("clients.id") ~
      get[Option[String]]("clients.client_id") ~
      get[Option[String]]("clients.client_secret") ~
      get[Option[Long]]("clients.client_secret_expires_at") ~
      get[Option[String]]("clients.registration_access_token") ~
      get[Option[String]]("clients.registration_client_uri_path") ~
      get[Option[String]]("clients.contacts") ~
      get[Option[String]]("clients.application_type") ~
      get[Option[String]]("clients.client_name") ~
      get[Option[String]]("clients.logo_uri") ~
      get[Option[String]]("clients.tos_uri") ~
      get[Option[String]]("clients.redirect_uris") ~
      get[Option[String]]("clients.token_endpoint_auth_method") ~
      get[Option[String]]("clients.policy_uri") ~
      get[Option[String]]("clients.jwks_uri") ~
      get[Option[String]]("clients.jwk_encryption_uri") ~
      get[Option[String]]("clients.x509_uri") ~
      get[Option[String]]("clients.x509_encryption_uri") ~
      get[Option[String]]("clients.sector_identifier_uri") ~
      get[Option[String]]("clients.javascript_origin_uris") ~
      get[Option[String]]("clients.subject_type") ~
      get[Option[String]]("clients.request_object_signing_alg") ~
      get[Option[String]]("clients.userinfo_signed_response_alg") ~
      get[Option[String]]("clients.userinfo_encrypted_response_alg") ~
      get[Option[String]]("clients.userinfo_encrypted_response_enc") ~
      get[Option[String]]("clients.id_token_signed_response_alg") ~
      get[Option[String]]("clients.id_token_encrypted_response_alg") ~
      get[Option[String]]("clients.id_token_encrypted_response_enc") ~
      get[Option[Int]]("clients.default_max_age") ~
      get[Option[Boolean]]("clients.require_auth_time") ~
      get[Option[String]]("clients.default_acr_values") ~
      get[Option[String]]("clients.initiate_login_uri") ~
      get[Option[String]]("clients.post_logout_redirect_uri") ~
      get[Option[String]]("clients.request_uris") ~
      get[Option[String]]("clients.grant_types") ~
      get[Option[String]]("clients.response_types") map {
           case id~client_id~client_secret~client_secret_expires_at~registration_access_token~registration_client_uri_path~contacts~application_type~client_name~logo_uri~tos_uri~redirect_uris~token_endpoint_auth_method~policy_uri~jwks_uri~jwk_encryption_uri~x509_uri~x509_encryption_uri~sector_identifier_uri~javascript_origin_uris~subject_type~request_object_signing_alg~userinfo_signed_response_alg~userinfo_encrypted_response_alg~userinfo_encrypted_response_enc~id_token_signed_response_alg~id_token_encrypted_response_alg~id_token_encrypted_response_enc~default_max_age~require_auth_time~default_acr_values~initiate_login_uri~post_logout_redirect_uri~request_uris~grant_types~response_types
      => Client( Map(
                       "id"->id,
                       "client_id"->client_id,
                       "client_secret" -> client_secret,
                       "client_secret_expires_at" -> client_secret_expires_at,
                       "registration_access_token" -> registration_access_token,
                       "registration_client_uri_path" -> registration_client_uri_path,
                       "contacts" -> contacts,
                       "application_type" -> application_type,
                       "client_name" -> client_name,
                       "logo_uri" -> logo_uri,
                       "tos_uri" -> tos_uri,
                       "redirect_uris" -> redirect_uris,
                       "token_endpoint_auth_method" -> token_endpoint_auth_method,
                       "policy_uri" -> policy_uri,
                       "jwks_uri" -> jwks_uri,
                       "jwk_encryption_uri" -> jwk_encryption_uri,
                       "x509_uri" -> x509_uri,
                       "x509_encryption_uri" -> x509_encryption_uri,
                       "sector_identifier_uri" -> sector_identifier_uri,
                       "javascript_origin_uris" -> javascript_origin_uris,
                       "subject_type" -> subject_type,
                       "request_object_signing_alg" -> request_object_signing_alg,
                       "userinfo_signed_response_alg" -> userinfo_signed_response_alg,
                       "userinfo_encrypted_response_alg" -> userinfo_encrypted_response_alg,
                       "userinfo_encrypted_response_enc" -> userinfo_encrypted_response_enc,
                       "id_token_signed_response_alg" -> id_token_signed_response_alg,
                       "id_token_encrypted_response_alg" -> id_token_encrypted_response_alg,
                       "id_token_encrypted_response_enc" -> id_token_encrypted_response_enc,
                       "default_max_age" -> default_max_age,
                       "require_auth_time" -> require_auth_time,
                       "default_acr_values" -> default_acr_values,
                       "initiate_login_uri" -> initiate_login_uri,
                       "post_logout_redirect_uri" -> post_logout_redirect_uri,
                       "request_uris" -> request_uris,
                       "grant_types" -> grant_types,
                       "response_types" -> response_types
                     )
                  )
    }
  }

  /*
  * Finds Client By Client_id
  */
  def findByClientId(client_id : String): Option[Client] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from clients where client_id = {client_id}").on("client_id"->client_id).as(Client.simple.singleOpt)
      }
    }
    catch {
      case unknown : Throwable => {
        Logger.trace("Client.findByClientId exception " + unknown)
        None
      }
    }
  }

  /*
  * Finds Client By Client_id
  */
  def findByClientIdAndClientSecret(client_id : String, client_secret : String): Option[Client] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from clients where client_id = {client_id} and client_secret = {client_secret}").on("client_id"->client_id, "client_secret"->client_secret).as(Client.simple.singleOpt)
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
   * List all the Clients
   */
  def list(): List[Client] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from clients").as(Client.simple *)
      }
    }
    catch {
      case unknown : Throwable => { Logger.trace("Client.list exception " + unknown); List() }
    }
  }

  def paramsToInsert(params: Seq[(Any, ParameterValue[_])]): String =
    "(" + params.map(_._1).mkString(",") + ") VALUES " +
      "(" + params.map("{" + _._1 + "}").mkString(",") + ")"

  def paramsToUpdate(params: Seq[(Any, ParameterValue[_])]): String =
      "SET " + params.map({case(x,y) => x + "={" + x + "}"}).mkString(",") + " WHERE id={id}"

  def insertTable(ps: Seq[(Any, ParameterValue[_])]) = DB.withConnection { implicit c =>
    SQL("INSERT INTO clients " + paramsToInsert(ps)).on(ps:_*).execute
  }

  def updateTable(ps: Seq[(Any, ParameterValue[_])]) = DB.withConnection { implicit c =>
    SQL("UPDATE clients " + paramsToUpdate(ps)).on(ps:_*).execute
  }

  /** re-usable mapping */
  def toParams(client: Client): Seq[(Any, ParameterValue[_])] = Seq(
            "client_id"->client.fields("client_id"),
            "client_secret" -> client.fields("client_secret"),
            "client_secret_expires_at" -> client.fields("client_secret_expires_at"),
            "registration_access_token" -> client.fields("registration_access_token"),
            "registration_client_uri_path" -> client.fields("registration_client_uri_path"),
            "contacts" -> client.fields("contacts"),
            "application_type" -> client.fields("application_type"),
            "client_name" -> client.fields("client_name"),
            "logo_uri" -> client.fields("logo_uri"),
            "tos_uri" -> client.fields("tos_uri"),
            "redirect_uris" -> client.fields("redirect_uris"),
            "token_endpoint_auth_method" -> client.fields("token_endpoint_auth_method"),
            "policy_uri" -> client.fields("policy_uri"),
            "jwks_uri" -> client.fields("jwks_uri"),
            "jwk_encryption_uri" -> client.fields("jwk_encryption_uri"),
            "x509_uri" -> client.fields("x509_uri"),
            "x509_encryption_uri" -> client.fields("x509_encryption_uri"),
            "sector_identifier_uri" -> client.fields("sector_identifier_uri"),
            "javascript_origin_uris" -> client.fields("javascript_origin_uris"),
            "subject_type" -> client.fields("subject_type"),
            "request_object_signing_alg" -> client.fields("request_object_signing_alg"),
            "userinfo_signed_response_alg" -> client.fields("userinfo_signed_response_alg"),
            "userinfo_encrypted_response_alg" -> client.fields("userinfo_encrypted_response_alg"),
            "userinfo_encrypted_response_enc" -> client.fields("userinfo_encrypted_response_enc"),
            "id_token_signed_response_alg" -> client.fields("id_token_signed_response_alg"),
            "id_token_encrypted_response_alg" -> client.fields("id_token_encrypted_response_alg"),
            "id_token_encrypted_response_enc" -> client.fields("id_token_encrypted_response_enc"),
            "default_max_age" -> client.fields("default_max_age"),
            "require_auth_time" -> client.fields("require_auth_time"),
            "default_acr_values" -> client.fields("default_acr_values"),
            "initiate_login_uri" -> client.fields("initiate_login_uri"),
            "post_logout_redirect_uri" -> client.fields("post_logout_redirect_uri"),
            "request_uris" -> client.fields("request_uris"),
            "grant_types" -> client.fields("grant_types"),
            "response_types" -> client.fields("response_types")
  )


  def insert(c: Client) { insertTable(toParams(c)) }


  /**
   * Update a client.
   *
   * @param client The client values.
   */
  def update(client: Client) = {
    val s1 : Seq[(Any, ParameterValue[_])] = Seq("id" -> client.fields("id"))
    updateTable(toParams(client)++s1)
  }

  /**
   * Update a client.
   *
   * @param id The client id
   * @param client The client values.
   */
  def update1(id: Long, client: Client) = {

//    val temp = client.fields.toSeq.map({case(x,y) => (x,y) match {
//      case (x, None) => (x, Option.empty)
//      case (x, y : Option[Any]) => (x, y.get)
//    }})

//    Logger.trace("temp = " +  temp)

    DB.withConnection { implicit connection =>
      SQL(
        """
          update clients
          set default_acr_values = {default_acr_values}
          where id = {id}
        """
      ).on(
        'id -> id,
//        "client_id"->client.fields("client_id"),
//        "client_secret" -> client.fields("client_secret"),
//        "client_secret_expires_at" -> client.fields("client_secret_expires_at"),
//        "registration_access_token" -> client.fields("registration_access_token"),
//        "registration_client_uri_path" -> client.fields("registration_client_uri_path"),
//        "contacts" -> client.fields("contacts"),
//        "application_type" -> client.fields("application_type"),
//        "client_name" -> client.fields("client_name"),
//        "logo_uri" -> client.fields("logo_uri"),
//        "tos_uri" -> client.fields("tos_uri"),
//        "redirect_uris" -> client.fields("redirect_uris"),
//        "token_endpoint_auth_method" -> client.fields("token_endpoint_auth_method"),
//        "policy_uri" -> client.fields("policy_uri"),
//        "jwks_uri" -> client.fields("jwks_uri"),
//        "jwk_encryption_uri" -> client.fields("jwk_encryption_uri"),
//        "x509_uri" -> client.fields("x509_uri"),
//        "x509_encryption_uri" -> client.fields("x509_encryption_uri"),
//        "sector_identifier_uri" -> client.fields("sector_identifier_uri"),
//        "javascript_origin_uris" -> client.fields("javascript_origin_uris"),
//        "subject_type" -> client.fields("subject_type"),
//        "request_object_signing_alg" -> client.fields("request_object_signing_alg"),
//        "userinfo_signed_response_alg" -> client.fields("userinfo_signed_response_alg"),
//        "userinfo_encrypted_response_alg" -> client.fields("userinfo_encrypted_response_alg"),
//        "userinfo_encrypted_response_enc" -> client.fields("userinfo_encrypted_response_enc"),
//        "id_token_signed_response_alg" -> client.fields("id_token_signed_response_alg"),
//        "id_token_encrypted_response_alg" -> client.fields("id_token_encrypted_response_alg"),
//        "id_token_encrypted_response_enc" -> client.fields("id_token_encrypted_response_enc"),
//        "default_max_age" -> client.fields("default_max_age"),
//        "require_auth_time" -> client.fields("require_auth_time"),
//        "default_acr_values" -> client.fields("default_acr_values"),
//        "initiate_login_uri" -> client.fields("initiate_login_uri"),
//        "post_logout_redirect_uri" -> client.fields("post_logout_redirect_uri"),
//        "request_uris" -> client.fields("request_uris"),
//        "grant_types" -> client.fields("grant_types"),
//        "response_types" -> client.fields("response_types"),
          "default_acr_values" -> None


      ).executeUpdate()
    }
  }

/*
        client.fields.toSeq.map({case(x,y) => (x,y) match {
          case (x, None) => (x.asInstanceOf[Any], ParameterValue(Option.empty))),
          case (x, y : Option[Any]) => (x.asInstanceOf[Any], ParameterValue(y)))
        }}):_*,
        'id -> id

 */

  /**
   * Insert a new client.
   *
   * @param client The token values.
   */
  def insert1(client: Client) = {
    DB.withConnection { implicit connection =>
      SQL(
        """
          insert into token (`account_id`, `token`, `token_type`, `client`, `details`, `issued_at`, `expiration_at`, `info` ) values (
            {account_id}, {token}, {token_type}, {client}, {details}, {issued_at}, {expiration_at}, {info}
          )
        """
      ).on(
        'account_id -> client.fields("account_id")
      ).executeUpdate()
    }
  }

  /**
   * Delete a client.
   *
   * @param id Id of the client to delete.
   */
  def delete(id: Long) = {
    DB.withConnection { implicit connection =>
      SQL("delete from clients where id = {id}").on('id -> id).executeUpdate()
    }
  }




}