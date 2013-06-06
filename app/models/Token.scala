package models

import java.util.{Date}
import java.sql.Timestamp

import play.api.Logger
import play.api.db._
import play.api.Play.current
import play.api.libs.json
import anorm._
import anorm.SqlParser._
import org.joda.time._
import org.joda.time.format._
import utils.AnormExtensions._
import play.api.libs.json._
import org.apache.commons.lang3.RandomStringUtils


/*

  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) NOT NULL,
  `token` text NOT NULL,
  `token_type` tinyint(4) DEFAULT '1',
  `client` varchar(255) NOT NULL,
  `details` text,
  `issued_at` datetime NOT NULL,
  `expiration_at` datetime NOT NULL,
  `info` text,
 */
case class Token(id: Long, var account_id: Long, var token: String, var token_type: Option[Int], var client: Option[String], var details: Option[String], var issued_at: Option[DateTime], var expiration_at: Option[DateTime], var info: Option[String])


/**
 * Created with IntelliJ IDEA.
 * User: edmund
 * Date: 5/20/13
 * Time: 3:58 PM
 * To change this template use File | Settings | File Templates.
 */
object Token {

  // -- Parsers

  /**
   * Parse a Computer from a ResultSet
   */
  val simple = {
      get[Long]("tokens.id") ~
      get[Long]("tokens.account_id") ~
      get[String]("tokens.token") ~
      get[Option[Int]]("tokens.token_type") ~
      get[Option[String]]("tokens.client") ~
      get[Option[String]]("tokens.details") ~
      get[Option[DateTime]]("tokens.issued_at") ~
      get[Option[DateTime]]("tokens.expiration_at") ~
      get[Option[String]]("tokens.info") map {
      case id~account_id~token~token_type~client~details~issued_at~expiration_at~info => Token(id, account_id, token, token_type, client, details, issued_at, expiration_at, info)
    }
  }


  /**
   * Finds Token By Token Name
   * @return Option[Token]
   */
  def findByName(token : String): Option[Token] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from tokens where token = {token}").on("token"->token).as(Token.simple.singleOpt)
      }
    }
    catch {
      case unknown : Throwable => {
        Logger.trace("Token.findByName exception " + unknown)
        None
      }
    }
  }


  def findByNameAndType(name : String, tokenType : Int): Option[Token] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from tokens where token = {token} and token_type = {token_type}").on("token"->name, "token_type"->tokenType).as(Token.simple.singleOpt)
      }
    }
    catch {
      case unknown : Throwable => {
        Logger.trace("Token.findByName exception " + unknown)
        None
      }
    }
  }

  def findCodeByName(name : String): Option[Token] = {
    findByNameAndType(name, 0)
  }

  def findAccessTokenByName(name : String): Option[Token] = {
    findByNameAndType(name, 1)
  }

  def findRefreshTokenByName(name : String): Option[Token] = {
    findByNameAndType(name, 2)
  }

  /**
   * List all the Tokens
   * @return List[Token]
   */
  def list(): List[Token] = {
    try {
      DB.withConnection { implicit conn =>
        SQL("select * from tokens").as(Token.simple *)
      }
    }
    catch {
      case unknown : Throwable => { Logger.trace("Token.list exception " + unknown); List() }
    }
  }

  def paramsToInsert(params: Seq[(Any, ParameterValue[_])]): String =
    "(" + params.map(_._1).mkString(",") + ") VALUES " +
      "(" + params.map("{" + _._1 + "}").mkString(",") + ")"

  def paramsToUpdate(params: Seq[(Any, ParameterValue[_])]): String =
    "SET " + params.map({case(x,y) => x + "={" + x + "}"}).mkString(",") + " WHERE id={id}"

  def insertTable(ps: Seq[(Any, ParameterValue[_])]) = DB.withConnection { implicit c =>
    SQL("INSERT INTO tokens " + paramsToInsert(ps)).on(ps:_*).execute
  }

  def updateTable(ps: Seq[(Any, ParameterValue[_])]) = DB.withConnection { implicit c =>
    SQL("UPDATE tokens " + paramsToUpdate(ps)).on(ps:_*).execute
  }

  /** re-usable mapping */
  def toParams(token: Token): Seq[(Any, ParameterValue[_])] = Seq(
    "account_id" -> token.account_id,
    "token" -> token.token,
    "token_type" -> token.token_type,
    "client" -> token.client,
    "details" -> token.details,
    "issued_at" -> token.issued_at,
    "expiration_at" -> token.expiration_at,
    "info" -> token.info
    )


  def insert(token: Token) { insertTable(toParams(token)) }


  /**
   * Update a client.
   *
   * @param token The client values.
   */
  def update(token: Token) = {
    val s1 : Seq[(Any, ParameterValue[_])] = Seq("id" -> token.id)
    updateTable(toParams(token)++s1)
  }



  /**
   * Update a token.
   *
   * @param id The token id
   * @param token The token values.
   */
  def update1(id: Long, token: Token) = {
    DB.withConnection { implicit connection =>
      SQL(
        """
          update tokens
          set `account_id` = {account_id},
              `token` = {token},
              `token_type` = {token_type},
              `client` = {client},
              `details` = {details},
              `issued_at` = {issued_at},
              `expiration_at` = {expiration_at},
              `info` = {info}
          where id = {id}
        """
      ).on(
        'id -> id,
        'account_id -> token.account_id,
        'token -> token.token,
        'token_type -> token.token_type,
        'client -> token.client,
        'details -> token.details,
        'issued_at -> token.issued_at,
        'expiration_at -> token.expiration_at,
        'info -> token.info
      ).executeUpdate()
    }
  }

  /**
   * Insert a new token.
   *
   * @param token The token values.
   */
  def insert1(token: Token) = {
    DB.withConnection { implicit connection =>
      SQL(
        """
          insert into token (`account_id`, `token`, `token_type`, `client`, `details`, `issued_at`, `expiration_at`, `info` ) values (
            {account_id}, {token}, {token_type}, {client}, {details}, {issued_at}, {expiration_at}, {info}
          )
        """
      ).on(
      'account_id -> token.account_id,
      'token -> token.token,
      'token_type -> token.token_type,
      'client -> token.client,
      'details -> token.details,
      'issued_at -> token.issued_at,
      'expiration_at -> token.expiration_at,
      'info -> token.info
      ).executeUpdate()
    }
  }

  /**
   * Delete a token.
   *
   * @param id Id of the token to delete.
   */
  def delete(id: Long) = {
    DB.withConnection { implicit connection =>
      SQL("delete from tokens where id = {id}").on('id -> id).executeUpdate()
    }
  }

/*
function create_token_info($uname, $confirm=0, $atype="none", $persona=NULL, $attribute_list=NULL, $get=NULL, $req=NULL) {
    while(true) {
        $token_name = base64url_encode(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
        if(!db_find_token($token_name))
            break;
    }
    $arr = Array();
    $arr['name'] = $token_name;
    $expires_in = 60; //in seconds
    $arr['e'] = time()+ $expires_in;
    $arr['u'] = $uname;
    $arr['y'] = $token_type;

    //    echo "<h1>atype:".$atype."</h1>";
    if($atype=="none" ) {
        $atype=0;
    } elseif ($atype=="signed") {
        $atype=1;
    } elseif($atype=='encrypted') {
        $atype=2;
    }
    $arr['t'] = $atype; // 0=none, 1=signed, 2=encrypted
    $arr['p'] = $persona;
    $arr['l'] = $attribute_list;
    $arr['c'] = $confirm; // 1=ax confirmed.
    $arr['g'] = $get;
    $arr['r'] = $req;
    return $arr;
}
   */


  def create_token_info(username : String, persona : String, attribute_list : List[String], get : JsObject, req : JsObject) : JsObject = {
    Json.obj(
              "name" -> RandomStringUtils.randomAlphanumeric(32),
              "e" -> new Timestamp(DateTime.now().plusMinutes(10).getMillis).getTime,
              "uname" -> username ,
              "p" -> persona,
              "l" -> JsArray(attribute_list.map(x => JsString(x)).toSeq),
              "g" -> get,
              "r" -> req
            )
  }

  def create_token_info(username : String, persona : String, attribute_list : List[String], get : Map[String, String], req : Map[String, String]) : JsObject = {
    Json.obj(
      "name" -> RandomStringUtils.randomAlphanumeric(32),
      "e" -> new Timestamp(DateTime.now().plusMinutes(10).getMillis).getTime,
      "uname" -> username ,
      "p" -> persona,
      "l" -> JsArray(attribute_list.map(x => JsString(x)).toSeq),
      "g" -> JsObject(get.map({case(x,y) => (x, JsString(y))}).toSeq),
      "r" -> JsObject(req.map({case(x,y) => (x, JsString(y))}).toSeq)
    )
  }
}
